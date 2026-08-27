import yaml

def parse_config(yaml_string):
    # Insecure Deserialization (YAML) [CWE-502]
    data = yaml.load(yaml_string, Loader=yaml.Loader)
    return data
