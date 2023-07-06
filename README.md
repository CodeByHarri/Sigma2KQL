# Sigma2KQL
Sigma Queries turned into KQL for Defender using [pysigma-backend-microsoft365defender](https://github.com/AttackIQ/pySigma-backend-microsoft365defender/tree/main)

Reproducible Example:
```python
!git clone https://github.com/SigmaHQ/sigma.git
!pip install pysigma-backend-microsoft365defender
import os, glob
path = 'sigma/rules/*/'
file_pattern = os.path.join(path,'*.yml')
file_list_a = glob.glob(file_pattern)

import yaml

def convert_to_string(yaml_dict):
    # We change default style of strings to None (it's '>' in PyYAML)
    # This means that PyYAML will choose style based on the data
    yaml.SafeDumper.org_represent_str = yaml.SafeDumper.represent_str
    def repr_str(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.org_represent_str(data)
    yaml.add_representer(str, repr_str, Dumper=yaml.SafeDumper)

    yaml_str = yaml.dump(yaml_dict, default_flow_style=False, Dumper=yaml.SafeDumper)
    return yaml_str

from sigma.rule import SigmaRule
from sigma.backends.microsoft365defender import Microsoft365DefenderBackend
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline


for yml in detections_yml_paths:
  with open(yml) as yaml_file:
    try:
      yaml_contents = load(yaml_file, Loader=SafeLoader)
      # Define an example rule as a YAML str
      sigma_rule = SigmaRule.from_yaml(convert_to_string(yaml_contents))
      # Create backend, which automatically adds the pipeline
      m365def_backend = Microsoft365DefenderBackend()

      # Or apply the pipeline manually
      pipeline = microsoft_365_defender_pipeline()
      pipeline.apply(sigma_rule)

      # Convert the rule
      print(sigma_rule.title + " KQL Query: \n")
      kql_query = m365def_backend.convert_rule(sigma_rule)[0]
      print(kql_query)
      print("\n \n ")

      # Write the KQL query to a .kql file
      with open('/KQL/'+sigma_rule.title.replace(' ', '_') + '.kql', 'w') as kql_file:
        # Write metadata as comments
        kql_file.write(f'// Author: {yaml_contents.get("author", "")}\n')
        kql_file.write(f'// Date: {yaml_contents.get("date", "")}\n')
        kql_file.write(f'// Level: {yaml_contents.get("level", "")}\n')
        kql_file.write(f'// Description: {yaml_contents.get("description", "")}\n')
        # Here it's assumed that 'tags' is a list
        tags = yaml_contents.get("tags", [])
        kql_file.write(f'// Tags: {", ".join(tags) if tags else ""}\n')
        # Write the actual KQL query
        kql_file.write(kql_query)
        
    except:
      print(sigma_rule.title + " KQL Query: \n")
      print('SigmaTransformationError: Rule category not yet supported by the Microsoft 365 Defender Sigma backend.')
```
