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

from json import dumps
from typing import Any

from flask import Flask, request, Response

from rucio.api.lock import get_replica_locks_for_rule_id
from rucio.api.migration import add_migration
from rucio.common.exception import InputValidationError, InsufficientAccountLimit, RuleNotFound, AccessDenied, InvalidRSEExpression, \
    InvalidReplicationRule, DataIdentifierNotFound, InsufficientTargetRSEs, ReplicationRuleCreationTemporaryFailed, \
    InvalidRuleWeight, StagingAreaRuleRequiresLifetime, DuplicateRule, InvalidObject, AccountNotFound, \
    RuleReplaceFailed, ScratchDiskLifetimeConflict, ManualRuleApprovalBlocked, UnsupportedOperation
from rucio.common.utils import render_json, APIEncoder
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import check_accept_header_wrapper_flask, parse_scope_name, try_stream, \
    response_headers, generate_http_error_flask, ErrorHandlingMethodView, json_parameters, param_get


class Migration(ErrorHandlingMethodView):
    """ REST APIs for all rules. """

    def post(self):
        """
        ---
        summary: Create a new replication rule
        tags:
          - Rule
        requestBody:
          description: Parameters for the new rule.
          content:
            'application/json':
              schema:
                type: object
                required:
                - dids
                - account
                - copies
                - rse_expression
                properties:
                  dids:
                    description: The list of data identifiers.
                    type: array
                    items:
                      type: string
                  account:
                    description: The account of the issuer.
                    type: string
                  copies:
                    description: The number of replicas.
                    type: integer
                  rse_expression:
                    description: The rse expression which gets resolved into a list of RSEs.
                    type: string
                  grouping:
                    description: The grouping of the files to take into account. (ALL, DATASET, NONE)
                    type: string
                  weight:
                     description: Weighting scheme to be used.
                     type: number
                  lifetime:
                     description: The lifetime of the replication rule in seconds.
                     type: integer
                  locked:
                     description: If the rule is locked.
                     type: boolean
                  subscription_id:
                     description: The subscription_id, if the rule is created by a subscription.
                     type: string
                  sourse_replica_expression:
                     description: Only use replicas as source from these RSEs.
                     type: string
                  activity:
                     description: Activity to be passed to the conveyor.
                     type: string
                  notify:
                     description: Notification setting of the rule ('Y', 'N', 'C'; None = 'N').
                     type: string
                  purge_replicas:
                     description: Purge setting if a replica should be directly deleted after the rule is deleted.
                     type: boolean
                  ignore_availability:
                     description: Option to ignore the availability of RSEs.
                     type: boolean
                  comments:
                     description: Comment about the rule.
                     type: string
                  ask_approval:
                     description: Ask for approval for this rule.
                     type: boolean
                  asynchronous:
                     description: Create replication rule asynchronously by the judge-injector.
                     type: boolean
                  priority:
                     description: Priority of the rule and the transfers which should be submitted.
                     type: integer
                  split_container:
                     description: Should a container rule be split into individual dataset rules.
                     type: boolean
                  meta:
                     description: Dictionary with metadata from the WFMS.
                     type: string
        responses:
          201:
            description: Rule created.
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: string
                    description: Id of each created rule.
          401:
            description: Invalid Auth Token
          404:
            description: No rule found for the given id
          409:
            description: |
              - Invalid Replication Rule
              - Duplicate Replication Rule
              - Insufficient Target RSEs
              - Insufficient Account Limit
              - Invalid RSE Expression
              - Replication Rule Creation Temporary Failed,
              - Invalid Rule Weight
              - Staging Area Rule Requires Lifetime
              - Scratch Disk Lifetime Conflict
              - Manual Rule Approval Blocked
              - Invalid Object
        """
        parameters = json_parameters()
        dids = param_get(parameters, 'dids')
        rse_expression = param_get(parameters, 'rse_expression')
        try:
            rule_ids = add_migration(
                dids=dids,
                rse_expression=rse_expression,
                weight=param_get(parameters, 'weight', default=None),
                issuer=request.environ.get('issuer'),
                vo=request.environ.get('vo'),
            )
        except Exception as error:
            return generate_http_error_flask(409, error)

        return Response(dumps(rule_ids), status=201)

def blueprint():
    bp = AuthenticatedBlueprint('migration', __name__, url_prefix='/migration')

    all_rule_view = Migration.as_view('all_rule')
    bp.add_url_rule('/', view_func=all_rule_view, methods=['post'])

    bp.after_request(response_headers)
    return bp


def make_doc():
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
