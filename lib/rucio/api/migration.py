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

from typing import Any, TYPE_CHECKING

from rucio.common.types import InternalAccount, InternalScope
from rucio.core import migration
from rucio.db.sqla.session import transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

@transactional_session
def add_migration(dids, rse_expression, issuer, vo='def', *, session: "Session"): 
     """
    Adds a replication rule.

    :param dids:                       The data identifier set.
    :param rse_expression:             Boolean string expression to give the list of RSEs.
    """
    account = issuer

    account = InternalAccount(account, vo=vo)
    for d in dids:
        d['scope'] = InternalScope(d['scope'], vo=vo)

    return migration.add_migration(account=account,
                         dids=dids,
                         account=account,
                         rse_expression=rse_expression,
                         session=session)

