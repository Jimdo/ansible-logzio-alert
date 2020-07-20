# ansible-logzio-alert

[![Build Status](https://travis-ci.org/Jimdo/ansible-logzio-alert.svg?branch=master)](https://travis-ci.org/Jimdo/ansible-logzio-alert) [![Ansible Galaxy](https://img.shields.io/badge/galaxy-Jimdo.logzio-alert-blue.svg?style=flat)](https://galaxy.ansible.com/Jimdo/logzio-alert/)

Ansible module to configure alerts in logz.io

## Installation

``` bash
$ ansible-galaxy install Jimdo.logzio-alert
```

## Documentation

### Module options

| Name                   | Required | Description                                                                                       | Default       |
|:-----------------------|:---------|:--------------------------------------------------------------------------------------------------|:--------------|
| name                   | true     | The unique name for the alert to create                                                           |               |
| logzio_api_endpoint    | false    | logz.io API endpoint                                                                              | api.logz.io   |
| logzio_api_token.      | false    | logz.io API token. If not set then the value of the LOGZIO_API_TOKEN environment variable is used |               |
| state                  | false    | Whether the alert should be present or absent                                                     | present       |
| description            | false    | The alert's description                                                                           |               |
| severity               | false    | The alert's severity (LOW, MEDIUM, or HIGH)                                                       | MEDIUM        |
| query                  | true     | The search query that returns messages for that we want to get the alert                          |               |
| operation              | false    | The operand for the comparison of the threshold                                                   | GREATER_THAN  |
| threshold              | false    | Threshold for the alert                                                                           | 0             |
| timeframe              | false    | Time interval in minutes that is considered for the calculation of the threshold                  | 10            |
| notification_emails    | false    | List of email addresses that should be notified                                                   |               |
| enabled                | false    | Whether this alert should be active                                                               | true          |
| suppress               | false    | Time interval in minutes that repeated notifications are suppressed                               | 5             |
| aggregation_type       | false    | The kind of aggregation we want to make over the aggregation field in the queried messages        | NONE          |
| aggregation_field      | false    | The field we want to select for aggregation                                                       |               |
| group_by_fields        | false    | List of fields by which to group the messages in the alert                                        |               |
| notification_endpoints | false    | List of names of the notification endpoints that should be triggered by this alert                |               |

## Examples

### Using the logzio_alert module in a Playbook

``` yml
---
- hosts: localhost
  connection: local
  gather_facts: False
  roles:
    - Jimdo.logzio-alert
  tasks:
    - name: Configure Logzio Alert 'Example'
      logzio_alert:
        name: "Example"
        query: >
          message: "some message"
          AND NOT message: "some other message"
        suppress: 60
        group_by_fields:
          - type
        notification_endpoints:
          - Slack Team Channel
```

``` bash
$ ansible-playbook alerts.yml
```
