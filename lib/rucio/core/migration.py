# -*- coding: utf-8 -*-
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
from configparser import NoOptionError, NoSectionError
from copy import deepcopy
from datetime import datetime, timedelta
from os import path
from re import match
from string import Template
from typing import TYPE_CHECKING, Any, Callable, Optional, Type, TypeVar

from sqlalchemy.exc import IntegrityError, StatementError

import rucio.core.did
import rucio.core.lock  # import get_replica_locks, get_files_and_replica_locks_of_dataset
import rucio.core.replica  # import get_and_lock_file_replicas, get_and_lock_file_replicas_for_dataset
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get
from rucio.db.sqla.session import read_session, transactional_session, stream_session
from rucio.db.sqla import models, filter_thread_work
from rucio.common.exception import (InvalidRSEExpression, InvalidReplicationRule, InsufficientAccountLimit,
                                    DataIdentifierNotFound, RuleNotFound, InputValidationError, RSEOverQuota,
                                    ReplicationRuleCreationTemporaryFailed, InsufficientTargetRSEs, RucioException,
                                    InvalidRuleWeight, StagingAreaRuleRequiresLifetime, DuplicateRule,
                                    InvalidObject, RSEWriteBlocked, RuleReplaceFailed, RequestNotFound,
                                    ManualRuleApprovalBlocked, UnsupportedOperation, UndefinedPolicy, InvalidValueForKey,
                                    InvalidSourceReplicaExpression, InvalidMigrationRule)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


REGION = make_region_memcached(expiration_time=900)
METRICS = MetricManager(module=__name__)
AutoApproveT = TypeVar('AutoApproveT', bound='AutoApprove')
last_query_time = None


@transactional_session
def add_migration(dids, account, rse_expression, notify=None, purge_replicas=False,
             ignore_availability=False, comment=None, ask_approval=False, asynchronous=False, ignore_account_limit=False,
             priority=3, delay_injection=None, split_container=False, meta=None, *, session: "Session", logger=logging.log):
    """
    Adds a replication rule for every did in dids

    :param dids:                       List of data identifiers.
    :param account:                    Account issuing the rule.
    :param rse_expression:             RSE expression which gets resolved into a list of rses.
    :param notify:                     Notification setting of the rule ('Y', 'N', 'C'; None = 'N').
    :param purge_replicas:             Purge setting if a replica should be directly deleted after the rule is deleted.
    :param ignore_availability:        Option to ignore the availability of RSEs.
    :param comment:                    Comment about the rule.
    :param ask_approval:               Ask for approval for this rule.
    :param asynchronous:               Create replication rule asynchronous
    
    
    y by the judge-injector.
    :param delay_injection:            Create replication after 'delay' seconds. Implies asynchronous=True.
    :param ignore_account_limit:       Ignore quota and create the rule outside of the account limits.
    :param priority:                   Priority of the rule and the transfers which should be submitted.
    :param split_container:            Should a container rule be split into individual dataset rules.
    :param meta:                       Dictionary with metadata from the WFMS.
    :param session:                    The database session in use.
    :param logger:                     Optional decorated logger that can be passed from the calling daemons or servers.
    :returns:                          A list of created replication rule ids.
    """
    
    for did in dids: 
        new_migration = models.Migration(account=account, 
                                     name=did.name, 
                                     scope=did.scope,
                                     did_type=did.did_type,
                                     rse_expression=rse_expression, 
                                     )
        
        try: 
            new_migration.save(session=session)
        except IntegrityError as error: 
            if match('.*ORA-00001.*', str(error.args[0])):
                raise DuplicateRule(error.args[0]) from error
            elif str(error.args[0]) == '(IntegrityError) UNIQUE constraint failed: rules.scope, rules.name, rules.account, rules.rse_expression, rules.copies':
                raise DuplicateRule(error.args[0]) from error
            raise InvalidMigrationRule(error.args[0]) from error

@read_session
def get_migration_records(total_workers: int, worker_number: int, limit: int = 100, *, session: Session):
    """
    Get migration records inserted since the last query.

    :param total_workers: Number of total workers.
    :param worker_number: ID of the executing worker.
    :param limit:         Maximum number of records to return.
    :param session:       Database session in use.
    """
    global last_query_time

    # Update the query to filter records based on the last query timestamp
    query = session.query(models.Migration).\
        order_by(models.Migration.created_at)

    if last_query_time:
        query = query.filter(models.Migration.created_at > last_query_time)

    query = filter_thread_work(session=session, query=query, total_threads=total_workers, thread_id=worker_number, hash_variable='id')

    if limit:
        records = query.limit(limit).all()
    else:
        records = query.all()

    # Update last query time for the next execution
    if records:
        last_query_time = max(record.created_at for record in records)

    return records