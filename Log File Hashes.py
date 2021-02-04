"""
Lab log file hash playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.fileHash", "in", "custom_list:Prior Hashes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Filehash_already_seen_format(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Format_filehash_not_seen(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Filehash_already_seen_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Filehash_already_seen_format() called')
    
    template = """The following hash: {0} has been seen previously!"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.fileHash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Filehash_already_seen_format")

    Comment_hash_seen(container=container)

    return

def Comment_hash_seen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Comment_hash_seen() called')

    formatted_data_1 = phantom.get_format_data(name='Filehash_already_seen_format__as_list')

    phantom.comment(container=container, comment=formatted_data_1)

    return

def Add_comment_and_update_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_comment_and_update_list() called')

    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash'])

    filtered_artifacts_item_1_0 = [item[0] for item in filtered_artifacts_data_1]

    phantom.comment(container=container, comment="Comment filehash not seen")

    phantom.add_list("Prior Hashes", filtered_artifacts_item_1_0)

    return

def Format_filehash_not_seen(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_filehash_not_seen() called')
    
    template = """Filehash {0} was never seen. Adding to known list!"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.fileHash",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_filehash_not_seen")

    Add_comment_and_update_list(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return