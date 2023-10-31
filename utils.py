import json
import os
import re
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis.analysis import Analysis
from constants import *

def load_permissions_to_apis():
    with open(PERMISSIONS_FILE, "r") as file:
        return json.load(file)

def extract_intents_from_manifest(a):
    intents = set()
    for activity_type in ["activities", "services", "receivers"]:
        for component in getattr(a, f"get_" + activity_type)():
            actions = a.get_intent_filters(activity_type, component).get("action", [])
            intents.update(actions)
    return intents

def extract_hardware_features(a):
    return {f"hardware::{feature}": 1 for feature in a.get_features()}

def extract_app_permissions(a):
    declared_permissions = set(a.get_permissions())
    return {f"app_permissions::name='{perm}'": 1 for perm in declared_permissions}, declared_permissions

def extract_intents_features(a):
    intents = extract_intents_from_manifest(a)
    return {f"intents::{intent}": 1 for intent in intents}

def extract_activities_features(a):
    return {f"activities::{activity}": 1 for activity in a.get_activities()}

def extract_s_and_r_features(a):
    return {f"s_and_r::{sr}": 1 for sr in a.get_receivers() + a.get_services()}

def extract_providers_features(a):
    return {f"providers::{provider}": 1 for provider in a.get_providers()}

def extract_api_calls_features(d, permissions_to_apis, declared_permissions):
    api_calls_to_permission = {}
    for permission in permissions_to_apis:
        for api_call in permissions_to_apis[permission]:
            api_calls_to_permission[api_call[0] + ";->" + api_call[1]] = permission

    features = {}
    used_api_calls = set()
    used_permissions = set()
    requested_api_calls = set()

    for current_class in d.get_classes():
        for method in current_class.get_methods():
            if method:
                for ins in method.get_instructions():
                    features.update(handle_instruction(ins, method, api_calls_to_permission, used_api_calls, used_permissions))

    for declared_permission in declared_permissions:
        if declared_permission in permissions_to_apis:
            for api_call in permissions_to_apis[declared_permission]:
                api_name, api_method = api_call[0], api_call[1]
                requested_api_calls.add(api_name + "->" + api_method)

    for api_call in used_api_calls:
        if api_call not in requested_api_calls:
            features[f"api_calls::{api_call}"] = 1

    for permission in declared_permissions.intersection(used_permissions):
        features[f"api_permissions::{permission}"] = 1

    return features

def handle_instruction(ins, bytecode, api_calls_to_permission, used_api_calls, used_permissions):
    features = {}
    # Handle const-string instruction for extracting URLs
    if ins.get_name().startswith("const-string"):
        method_code = ins.get_output().split(", ")[1][1:-1]
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', method_code)
        for url in urls:
            features[f"urls::{url}"] = 1

    # Handle invoke instruction for extracting API calls
    if ins.get_name().startswith("invoke") or ins.get_name().startswith("const-string"):
        call = ins.get_output().split(", ")[-1][1:-1]
        
        if ins.get_name().startswith("invoke"):
            filtered_call = call.replace("/", ".")
            call_without_parameters = filtered_call.split("(")[0]

            if call_without_parameters in api_calls_to_permission:
                used_api_calls.add(call_without_parameters)
                used_permissions.add(api_calls_to_permission[call_without_parameters])

        # Check if the call is in the list of suspicious API calls
        for possible_call in ALL_SUSPICIOUS_NAME_LIST:
            if possible_call in call:
                features[f"interesting_calls::{possible_call}"] = 1
                break

        # Check for Cipher-related calls
        if ins.get_name().startswith("invoke-static") and "Ljavax/crypto/Cipher;" in ins.get_output():
            for ins2 in bytecode.get_instructions():
                if ins2.get_name().startswith("const-string"):
                    for CIPHER_KEYWORD in CIPHER_KEYWORDS:
                        if CIPHER_KEYWORD in ins2.get_output():
                            cipher_algorithm = ins2.get_output().split(", ")[1][1:-1]
                            features[f"interesting_calls::Cipher({cipher_algorithm})"] = 1
                            break

        # Check for Base64 obfuscation calls
        if "Landroid/util/Base64;" in ins.get_output():
            features[f"interesting_calls::Obfuscation(Base64)"] = 1

    return features


def extract_features_from_apk(app_path):
    a = apk.APK(app_path)
    d = dvm.DalvikVMFormat(a.get_dex())
    dx = Analysis(d)
    
    features = {}
    permissions_to_apis = load_permissions_to_apis()

    features.update(extract_hardware_features(a))

    app_permissions, declared_permissions = extract_app_permissions(a)
    features.update(app_permissions)

    features.update(extract_intents_features(a))
    features.update(extract_activities_features(a))
    features.update(extract_s_and_r_features(a))
    features.update(extract_providers_features(a))

    features.update(extract_api_calls_features(d, permissions_to_apis, declared_permissions))

    return features
