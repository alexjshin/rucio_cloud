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

from dogpile.cache.api import NO_VALUE
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.exc import NoResultFound  # https://pydoc.dev/sqlalchemy/latest/sqlalchemy.exc.NoResultFound.html
from sqlalchemy.sql import func
from sqlalchemy.sql.expression import and_, or_, true, null, tuple_, false

import rucio.core.did
import rucio.core.lock  # import get_replica_locks, get_files_and_replica_locks_of_dataset
import rucio.core.replica  # import get_and_lock_file_replicas, get_and_lock_file_replicas_for_dataset
from rucio.common.cache import make_region_memcached
from rucio.common.config import config_get
from rucio.common.exception import (InvalidRSEExpression, InvalidReplicationRule, InsufficientAccountLimit,
                                    DataIdentifierNotFound, RuleNotFound, InputValidationError, RSEOverQuota,
                                    ReplicationRuleCreationTemporaryFailed, InsufficientTargetRSEs, RucioException,
                                    InvalidRuleWeight, StagingAreaRuleRequiresLifetime, DuplicateRule,
                                    InvalidObject, RSEWriteBlocked, RuleReplaceFailed, RequestNotFound,
                                    ManualRuleApprovalBlocked, UnsupportedOperation, UndefinedPolicy, InvalidValueForKey,
                                    InvalidSourceReplicaExpression)
from rucio.common.policy import policy_filter, get_scratchdisk_lifetime
from rucio.common.schema import validate_schema
from rucio.common.types import InternalScope, InternalAccount
from rucio.common.utils import str_to_date, sizefmt, chunks
from rucio.core import account_counter, rse_counter, request as request_core, transfer as transfer_core
from rucio.core.account import get_account
from rucio.core.account import has_account_attribute
from rucio.core.lifetime_exception import define_eol
from rucio.core.message import add_message
from rucio.core.monitor import MetricManager
from rucio.core.plugins import PolicyPackageAlgorithms
from rucio.core.rse import get_rse_name, list_rse_attributes, get_rse, get_rse_usage
from rucio.core.rse_expression_parser import parse_expression
from rucio.core.rse_selector import RSESelector
from rucio.core.rule_grouping import apply_rule_grouping, repair_stuck_locks_and_apply_rule_grouping, create_transfer_dict, apply_rule
from rucio.db.sqla import models, filter_thread_work
from rucio.db.sqla.constants import (LockState, ReplicaState, RuleState, RuleGrouping,
                                     DIDAvailability, DIDReEvaluation, DIDType, BadFilesStatus,
                                     RequestType, RuleNotification, OBSOLETE, RSEType)
from rucio.db.sqla.session import read_session, transactional_session, stream_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


REGION = make_region_memcached(expiration_time=900)
METRICS = MetricManager(module=__name__)
AutoApproveT = TypeVar('AutoApproveT', bound='AutoApprove')


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
    :param asynchronous:               Create replication rule asynchronousl
    
    
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
    


