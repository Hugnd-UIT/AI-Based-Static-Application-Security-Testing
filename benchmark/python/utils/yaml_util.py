import yaml

def parse_config(yaml_string):
    # Insecure Deserialization [CWE-502]
    data = yaml.load(yaml_string, Loader=yaml.Loader)
    return data
