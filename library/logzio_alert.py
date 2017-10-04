#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: logzio_alert
author: "Jimdo GmbH"
short_description: Manage and enforce logz.io alerts
description:
    - Manage and enforce logz.io alerts
options:
    name:
        required: true
        description:
            - The unique title for the alert to create

    logzio_api_endpoint:
        required: false
        description:
            - logz.io API endpoint.

    logzio_api_token:
        required: false
        description:
            - logz.io API token. If not set then the value of the LOGZIO_API_TOKEN environment variable is used.

    state:
        required: false
        default: present
        choices: [present, absent]
        description:
            - Whether the alert should be present or absent

    description:
        required: false
        description:
            - The alert's description

    severity:
        required: false
        default: MEDIUM
        choices: [LOW, MEDIUM, HIGH]
        description:
            - The alert's severity

    query:
        required: true
        description:
            - The search query that returns messages for that we want to get the alert

    operation:
        required: false
        default: GREATER_THAN
        choices: [LESS_THAN, GREATER_THAN, LESS_THAN_OR_EQUALS, GREATER_THAN_OR_EQUALS, EQUALS, NOT_EQUALS]
        description:
            - The operand for the comparison of the threshold

    threshold:
        required: false
        default: 0
        description:
            - Threshold for the alert

    timeframe:
        required: false
        default: 10
        description:
            - time interval in minutes that is considered for the calculation of the threshold

    notification_emails:
        required: false
        default: empty
        description:
            - list of email addresses that should be notified

    enabled:
        required: false
        default: true
        description:
            - whether this alert should be active

    suppression_interval:
        required: false
        default: 5
        description:
            - time interval in minutes that repeated notifications are suppressed

    aggregation_type:
        required: false
        default: NONE
        choices: [SUM, MIN, MAX, AVG, COUNT, NONE]
        description:
            - The kind of aggregation we want to make over the aggregation field in the queried messages.

    aggregation_field:
        required: false
        description:
            - The field we want to select for aggregation
            - Required, if aggregation_type is not 'NONE'

    group_by_fields:
        required: false
        default: empty
        description:
            - The list of fields by which to group the messages in the alert

    notification_endpoints:
        required: false
        default: empty
        description:
            - A list of titles of the notification endpoints that should be triggered by this alert
'''

EXAMPLES = '''
- logzio_alert:
    name: "Example Alert"
    query: >
      message: "some message"
      AND NOT message: "some other message"
    suppress: 60
    group_by_fields:
      - type
    notification_endpoints:
      - Slack Team Channel
'''

import httplib

from ansible.module_utils.basic import *

LOGZIO_DEFAULT_API_ENDPOINT = 'api.logz.io'

class LogzioResponse(object):
    def __init__(self, http_response):
        self.status = http_response.status

        body = http_response.read()
        self.payloadString = body
        try:
            self.payload = json.loads(body)
        except Exception as err:
            self.payload = body


class LogzioAlertConfiguration(object):
    def __init__(self, configuration):
        self.title = configuration['title']
        self.description = configuration['description']
        self.severity = configuration['severity']
        self.query_string = configuration['query_string']
        self.operation = configuration['operation']
        self.threshold = configuration['threshold']
        self.searchTimeFrameMinutes = configuration['searchTimeFrameMinutes']
        self.notificationEmails = configuration['notificationEmails']
        self.isEnabled = configuration['isEnabled']
        self.suppressNotificationsMinutes = configuration['suppressNotificationsMinutes']
        self.valueAggregationType = configuration['valueAggregationType']
        self.valueAggregationField = configuration['valueAggregationField']
        self.groupByAggregationFields = configuration['groupByAggregationFields']
        self.alertNotificationEndpoints = configuration['alertNotificationEndpoints']

    def validate(self):
        if self.valueAggregationType not in [None, 'NONE', 'COUNT'] and self.valueAggregationField is None:
            raise Exception("For aggregation, both 'aggregation_type' and 'aggregation_field' need to be configured (type was '%s')" % self.valueAggregationType)

    def __eq__(self, other):
        for k, v in self.__dict__.iteritems():
            if not k.startswith('_'):

                # compare all lists unordered
                if isinstance(v, list):
                    if frozenset(v) != frozenset(other.__dict__[k]):
                        return False

                    continue

                if v != other.__dict__[k]:
                    return False

        return True

    def __ne__(self, other):
        return not self.__eq__(other)


class LogzioAlert(object):
    def __init__(self, configuration):
        self.configuration = LogzioAlertConfiguration(configuration)

        self.id = configuration['alertId']


class LogzioNotificationEndpoint(object):
    def __init__(self, configuration):
        self.id = configuration['id']
        self.title = configuration['title']
        self.type = configuration['type']
        self.description = configuration['description']


class LogzioClient(object):
    def __init__(self, logzio_api_endpoint, logzio_api_token):
        self.logzio_api_endpoint = logzio_api_endpoint
        self.logzio_api_token = logzio_api_token

    def _request(self, path, method='GET', payload=None):
        headers = {
            'X-API-TOKEN': self.logzio_api_token,
            'Content-Type': 'application/json'
        }

        body = None
        if payload is not None:
            body = json.dumps(payload.__dict__)

        conn = httplib.HTTPSConnection(self.logzio_api_endpoint)
        conn.request(method, path, body, headers)
        return LogzioResponse(conn.getresponse())

    def get_notification_endpoints(self):
        response = self._request('/v1/alerts/notification-endpoints')
        if response.status == 200:
            endpoints = []
            for notification_endpoint in response.payload:
                endpoints.append(LogzioNotificationEndpoint(notification_endpoint))
            return endpoints
        else:
            raise Exception("Error retreiving notification endpoints: [%s] %s" % (response.status, response.payloadString))

    def get_alert_by_title(self, alert_title):
        response = self._request('/v1/alerts')
        if response.status == 200:
            for alert in response.payload:
                if alert['title'] == alert_title:
                    return LogzioAlert(alert)
            return None
        else:
            raise Exception("Error retreiving alert '%s': [%s] %s" % (alert_title, response.status, response.payloadString))

    def create_alert(self, alert_title, alert_configuration):
        response = self._request('/v1/alerts', 'POST', alert_configuration)
        if response.status != 200:
            raise Exception("Error creating alert with title '%s': [%s] %s" % (alert_title, response.status, response.payloadString))

    def update_alert(self, alert_id, alert_title, alert_configuration):
        response = self._request('/v1/alerts/%s' % alert_id, 'PUT', alert_configuration)
        if response.status == 200:
            return True
        else:
            raise Exception("Error updating alert with title '%s': [%s] %s" % (alert_title, response.status, response.payloadString))

    def delete_alert(self, alert_id, alert_title):
        response = self._request('/v1/alerts/%s' % alert_id, 'DELETE')
        if response.status == 200:
            return True
        else:
            raise Exception("Error deleting alert with title '%s': [%s] %s" % (alert_title, response.status, response.payloadString))


class LogzioStateEnforcerResult(object):
    def __init__(self, changed, actions):
        self.changed = changed
        self.actions = actions


class LogzioStateEnforcer(object):
    def __init__(self, client):
        self.client = client

    def apply_configuration(self, alert_title, alert_configuration):
        actions = []

        alert = self.client.get_alert_by_title(alert_title)

        if alert is None:
            self.client.create_alert(alert_title, alert_configuration)
            actions.append("Created new alert %s" % alert_title)
        else:
            if alert.configuration != alert_configuration:
                self.client.update_alert(alert.id, alert_title, alert_configuration)
                actions.append("Update alert %s" % alert_title)

        changed = len(actions) > 0
        return LogzioStateEnforcerResult(actions=actions, changed=changed)

    def delete_alert(self, alert_title):
        alert = self.client.get_alert_by_title(alert_title)

        if alert is None:
            return LogzioStateEnforcerResult(actions=[], changed=False)

        changed = self.client.delete_alert(alert.id, alert_title)

        actions = []
        if changed:
            actions.append('Deleted alert %s' % alert_title)

        return LogzioStateEnforcerResult(actions=actions, changed=changed)


class LogzioAlertModule(object):
    def __init__(self):
        self.module = AnsibleModule(
            argument_spec=dict(
                state=dict(default='present', choices=['present', 'absent'], type='str'),
                logzio_api_endpoint=dict(type='str'),
                logzio_api_token=dict(no_log=True, type='str'),
                name=dict(required=True, type='str'),
                description=dict(required=False, type='str'),
                severity=dict(required=False, default='MEDIUM', choices=['LOW', 'MEDIUM', 'HIGH'], type='str'),
                query=dict(required=True, type='str'),
                operation=dict(required=False, default='GREATER_THAN', choices=['LESS_THAN', 'GREATER_THAN', 'LESS_THAN_OR_EQUALS', 'GREATER_THAN_OR_EQUALS', 'EQUALS', 'NOT_EQUALS'], type='str'),
                threshold=dict(required=False, default=0, type='float'),
                timeframe=dict(required=False, default=10, type='int'),
                notification_emails=dict(required=False, default=[], type='list'),
                enabled=dict(required=False, default=True, type='bool'),
                suppress=dict(required=False, default=5, type='int'),
                aggregation_type=dict(required=False, default='NONE', choices=['SUM', 'MIN', 'MAX', 'AVG', 'COUNT', 'NONE'], type='str'),
                aggregation_field=dict(required=False, type='str'),
                group_by_fields=dict(required=False, default=[], type='list'),
                notification_endpoints=dict(required=False, default=[], type='list')
            ),
            supports_check_mode=False
        )

        self.client = self._create_client()
        self.enforcer = self._create_enforcer()

    def _create_client(self):
        logzio_api_endpoint = self.module.params['logzio_api_endpoint']
        if not logzio_api_endpoint:
            if 'LOGZIO_API_ENDPOINT' in os.environ:
                logzio_api_endpoint = os.environ['LOGZIO_API_ENDPOINT']
            else:
                logzio_api_endpoint = LOGZIO_DEFAULT_API_ENDPOINT

        logzio_api_token = self.module.params['logzio_api_token']
        if not logzio_api_token:
            if 'LOGZIO_API_TOKEN' in os.environ:
                logzio_api_token = os.environ['LOGZIO_API_TOKEN']
            else:
                self.module.fail_json(msg="A logz.io API Token key is required for this module. Please set it and try again")

        return LogzioClient(logzio_api_endpoint, logzio_api_token)

    def _create_enforcer(self):
        return LogzioStateEnforcer(self.client)

    def alert_configuration(self):
        notification_endpoint_ids = self.notification_endpoints_to_ids(self.module.params['notification_endpoints'])
        configuration = LogzioAlertConfiguration({
            'title': self.module.params['name'],
            'description': self.module.params['description'],
            'severity': self.module.params['severity'],
            'query_string': self.module.params['query'],
            'operation': self.module.params['operation'],
            'threshold': self.module.params['threshold'],
            'searchTimeFrameMinutes': self.module.params['timeframe'],
            'notificationEmails': self.module.params['notification_emails'],
            'isEnabled': self.module.params['enabled'],
            'suppressNotificationsMinutes': self.module.params['suppress'],
            'valueAggregationType': self.module.params['aggregation_type'],
            'valueAggregationField': self.module.params['aggregation_field'],
            'groupByAggregationFields': self.module.params['group_by_fields'],
            'alertNotificationEndpoints': notification_endpoint_ids,
        })
        configuration.validate()

        return configuration

    def notification_endpoints_to_ids(self, titles):
        if titles is None:
            return []

        endpoints = self.client.get_notification_endpoints()

        ids = []
        for title in titles:
            matching_endpoints = [e for e in endpoints if e.title == title]
            if len(matching_endpoints) == 0:
                raise Exception("No endpoint titled '%s' found" % title)
            ids.append(matching_endpoints[0].id)
        return ids

    def run(self):
        try:
            alert_title = self.module.params['name']

            if self.module.params['state'] == 'absent':
                result = self.enforcer.delete_alert(alert_title)

                self.module.exit_json(changed=result.changed, actions=result.actions)
            else:
                result = self.enforcer.apply_configuration(alert_title, self.alert_configuration())
                self.module.exit_json(changed=result.changed, actions=result.actions)

        except Exception as err:
            self.module.fail_json(msg=err.message)


def main():
    logzio_module = LogzioAlertModule()
    logzio_module.run()


if __name__ == '__main__':
    main()
