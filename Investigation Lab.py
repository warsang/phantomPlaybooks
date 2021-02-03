"""
Investigation Lab Playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'domain_reputation_2' block
    domain_reputation_2(container=container)

    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], callback=join_high_positives, name="geolocate_ip_1")

    return

def domain_reputation_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_2() called')

    # collect data for 'domain_reputation_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['virustotal'], callback=join_high_positives, name="domain_reputation_2")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=join_high_positives, name="file_reputation_1")

    return

"""
check to see if positive results from VirusTotal are above risk tolerance 
"""
def high_positives(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('high_positives() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 10],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Filter_destination_ip_null_values(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    filter_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_high_positives(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_high_positives() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['domain_reputation_2', 'geolocate_ip_1', 'file_reputation_1']):
        
        # call connected block "high_positives"
        high_positives(container=container, handle=handle)
    
    return

"""
Prompts IT to promote to case
"""
def Notify_IT(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Notify_IT() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """A potentially malicious file download has been detected on a local server with IP address {0}. Notify IT team?{0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.destinationAddress",
    ]

    #responses:
    response_types = [
        {
            "prompt": "Notify IT?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
        {
            "prompt": "Comments",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=10, name="Notify_IT", parameters=parameters, response_types=response_types, callback=Prompt_timeout)

    return

"""
Filter destination ip null values
"""
def Filter_destination_ip_null_values(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filter_destination_ip_null_values() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Filter_destination_ip_null_values:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Notify_IT(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Decision block for prompt timeout
"""
def Prompt_timeout(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_timeout() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT:action_result.status", "==", "\"success\""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Event_promote(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Prompt_timeout_api(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Did we decide to promote the event?
"""
def Event_promote(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Event_promote() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Notify_IT:action_result.summary.responses.0", "==", "\"Yes\""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_artifact_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    User_Declined(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Compose_comment(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Prepares the resolution comment
"""
def Compose_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Compose_comment() called')
    
    template = """“Virus positives {0} are below threshold 10, closing event.”"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:file_reputation_1:action_result.data.*.positives",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Compose_comment")

    Risk_threshold_is_below(container=container)

    return

def Risk_threshold_is_below(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Risk_threshold_is_below() called')

    formatted_data_1 = phantom.get_format_data(name='Compose_comment__as_list')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def Prompt_timeout_api(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Prompt_timeout_api() called')

    phantom.pin(container=container, data="", message="\"Awaiting Action\"", pin_type="card", pin_style="red", name="Awaiting_Action_pin")

    note_title = ""
    note_content = ""
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    phantom.comment(container=container, comment="“User failed to promote event within time limit.”")

    phantom.set_status(container=container, status="Closed")

    return

def User_Declined(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('User_Declined() called')

    results_data_1 = phantom.collect2(container=container, datapath=['Notify_IT:action_result.summary.responses.1'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.comment(container=container, comment=results_item_1_0)

    phantom.set_status(container=container, status="Closed")

    return

def Promote_to_Case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Promote_to_Case() called')
    
    # call playbook "phantomPlaybooks/Case Promotion Lab", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="phantomPlaybooks/Case Promotion Lab", container=container, name="Promote_to_Case")

    return

def add_artifact_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_artifact_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_artifact_1' call

    parameters = []
    
    # build parameters list for 'add_artifact_1' call
    parameters.append({
        'name': "Promote Reason",
        'container_id': "",
        'label': "event",
        'source_data_identifier': "Investigation lab",
        'cef_name': "reason",
        'cef_value': "the text message entered by the IT team in the user prompt",
        'cef_dictionary': "",
        'contains': "",
        'run_automation': False,
    })

    phantom.act(action="add artifact", parameters=parameters, assets=['phantom'], callback=Promote_to_Case, name="add_artifact_1")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    summary_json = phantom.get_summary()
    if 'result' in summary_json:
         for action_result in summary_json['result']:
             if 'action_run_id' in action_result:
                 action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                 phantom.debug(action_results)

    return