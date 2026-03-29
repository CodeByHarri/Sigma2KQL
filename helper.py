"""Helper script for converting sigma rules to kql for Microsoft Sentinel and Defender XDR."""
import os
import glob
import argparse
import yaml
from yaml import load, SafeLoader
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

# Parse command-line arguments
parser = argparse.ArgumentParser(
    description='Convert Sigma rules to KQL queries for Microsoft Sentinel and Defender XDR',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
Examples:
  python helper.py
  python helper.py --sigma-dir ./sigma --output-dir ./output
  python helper.py -s ../sigma -o ../KQL-Rules
    """
)
parser.add_argument(
    '--sigma-dir', '-s',
    type=str,
    default='./sigma',
    help='Path to the Sigma rules repository directory (default: ./sigma)'
)
parser.add_argument(
    '--output-dir', '-o',
    type=str,
    default='./KQL',
    help='Path to the output directory for KQL files (default: ./KQL)'
)

args = parser.parse_args()

print("Starting Script")

# Define Sigma rule folders to process
SIGMA_BASE = os.path.abspath(args.sigma_dir)
OUTPUT_BASE = os.path.abspath(args.output_dir)

RULE_FOLDERS = [
    "rules",
    "rules-compliance",
    "rules-dfir",
    "rules-emerging-threats",
    "rules-placeholder",
    "rules-threat-hunting"
]

print(f"Sigma base path: {SIGMA_BASE}")
print(f"Output base path: {OUTPUT_BASE}")
print(f"Rule folders to process: {', '.join(RULE_FOLDERS)}")
print("="*80)

def convert_to_string(yaml_dict):
    """Function converts yaml dict to string."""
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


def extract_mitre_tactic(tags):
    """Extract MITRE ATT&CK tactic from tags."""
    # MITRE tactics mapping - using hyphens as that's what Sigma uses
    tactics = {
        'attack.reconnaissance': 'Reconnaissance',
        'attack.resource-development': 'Resource Development',
        'attack.resource_development': 'Resource Development',
        'attack.initial-access': 'Initial Access',
        'attack.initial_access': 'Initial Access',
        'attack.execution': 'Execution',
        'attack.persistence': 'Persistence',
        'attack.privilege-escalation': 'Privilege Escalation',
        'attack.privilege_escalation': 'Privilege Escalation',
        'attack.defense-evasion': 'Defense Evasion',
        'attack.defense_evasion': 'Defense Evasion',
        'attack.credential-access': 'Credential Access',
        'attack.credential_access': 'Credential Access',
        'attack.discovery': 'Discovery',
        'attack.lateral-movement': 'Lateral Movement',
        'attack.lateral_movement': 'Lateral Movement',
        'attack.collection': 'Collection',
        'attack.command-and-control': 'Command and Control',
        'attack.command_and_control': 'Command and Control',
        'attack.exfiltration': 'Exfiltration',
        'attack.impact': 'Impact'
    }

    if not tags:
        return 'Uncategorized'

    # Find the first matching tactic
    for tag in tags:
        tag_lower = tag.lower()
        for tactic_key, tactic_name in tactics.items():
            if tag_lower.startswith(tactic_key):
                return tactic_name

    return 'Uncategorized'


# Overall Statistics
TOTAL_SUCCESSFUL = 0
TOTAL_FAILED = 0
overall_stats = {}

# Process each rule folder
for rule_folder in RULE_FOLDERS:
    print(f"\nProcessing: {rule_folder}")
    print("-"*80)

    # Get all YAML files from this rule folder
    PATH = os.path.join(SIGMA_BASE, rule_folder)
    file_pattern = os.path.join(PATH, '**', '*.yml')
    file_list = glob.glob(file_pattern, recursive=True)

    print(f"Found {len(file_list)} Sigma rule files in {rule_folder}")

    if not file_list:
        print(f"No files found in {rule_folder}, skipping...")
        continue

    # Statistics for this folder
    SUCCESSFUL_CONVERSIONS = 0
    FAILED_CONVERSIONS = 0
    tactic_stats = {}

    for idx, yml in enumerate(file_list, 1):
        try:
            with open(yml, encoding='utf-8') as yaml_file:
                yaml_contents = load(yaml_file, Loader=SafeLoader)

            # Define an example rule as a YAML str
            sigma_rule = SigmaRule.from_yaml(convert_to_string(yaml_contents))

            # Create backend with the pipeline
            pipeline = microsoft_xdr_pipeline()
            backend = KustoBackend(processing_pipeline=pipeline)

            # Convert the rule
            kql_query = backend.convert_rule(sigma_rule)[0]

            # Get MITRE tactic from tags
            tags = yaml_contents.get("tags", [])
            TACTIC_FOLDER = extract_mitre_tactic(tags)

            # Preserve original sigma repository folder structure for outputs
            # Compute the path of the YAML file relative to the sigma base
            rel_path = os.path.relpath(yml, SIGMA_BASE)
            rel_dir = os.path.dirname(rel_path)
            # If the file was at the top-level of SIGMA_BASE, fall back to rule_folder
            if rel_dir:
                OUTPUT_DIR = os.path.join(OUTPUT_BASE, rel_dir)
            else:
                OUTPUT_DIR = os.path.join(OUTPUT_BASE, rule_folder)
            os.makedirs(OUTPUT_DIR, exist_ok=True)

            # Use the original sigma rule filename (without extension)
            SOURCE_FILENAME = os.path.splitext(os.path.basename(yml))[0]
            output_file = os.path.join(OUTPUT_DIR, SOURCE_FILENAME + '.kql')

            with open(output_file, 'w', encoding='utf-8') as kql_file:
                # Write metadata as comments
                kql_file.write(f'// Title: {sigma_rule.title}\n')
                kql_file.write(f'// Author: {yaml_contents.get("author", "")}\n')
                kql_file.write(f'// Date: {yaml_contents.get("date", "")}\n')
                kql_file.write(f'// Level: {yaml_contents.get("level", "")}\n')
                
                # Handle multi-line descriptions
                description = yaml_contents.get("description", "")
                if description:
                    # Split by newlines and comment each line
                    desc_lines = description.split('\n')
                    kql_file.write(f'// Description: {desc_lines[0]}\n')
                    for line in desc_lines[1:]:
                        if line.strip():  # Only write non-empty lines
                            kql_file.write(f'// {line}\n')
                
                kql_file.write(f'// MITRE Tactic: {TACTIC_FOLDER}\n')
                kql_file.write(f'// Tags: {", ".join(tags) if tags else ""}\n')
                # Write reference to original sigma rule on GitHub
                rel_path_url = rel_path.replace('\\', '/')
                kql_file.write(f'// Reference: https://github.com/SigmaHQ/sigma/blob/master/{rel_path_url}\n')

                # Write false positives if present
                false_positives = yaml_contents.get("falsepositives", [])
                if false_positives:
                    # Filter out empty or "unknown" entries
                    valid_fps = [str(fp).strip() for fp in false_positives 
                                if fp and str(fp).strip() and str(fp).strip().lower() != 'unknown']
                    if valid_fps:
                        kql_file.write('// False Positives:\n')
                        for fp_str in valid_fps:
                            kql_file.write(f'//   - {fp_str}\n')

                kql_file.write('\n')
                # Write the actual KQL query
                kql_file.write(kql_query)

            SUCCESSFUL_CONVERSIONS += 1
            # Track by tactic
            tactic_stats[TACTIC_FOLDER] = tactic_stats.get(TACTIC_FOLDER, 0) + 1

            if SUCCESSFUL_CONVERSIONS % 10 == 0:
                print(f"[{idx}/{len(file_list)}] {rule_folder}: Converted: {SUCCESSFUL_CONVERSIONS}")
                print(f"Failed: {FAILED_CONVERSIONS}")

        except Exception as e:
            FAILED_CONVERSIONS += 1
            rule_name = yaml_contents.get('title', os.path.basename(yml)) if 'yaml_contents' in locals() else os.path.basename(yml)
            if FAILED_CONVERSIONS <= 5:  # Only show first 5 errors in detail
                print(f"[{idx}/{len(file_list)}] {rule_name} - Error: {str(e)[:100]}")
            # Continue to next file    # Print statistics for this folder
    print(f"\n{rule_folder} Summary:")
    print(f"  Successful: {SUCCESSFUL_CONVERSIONS}")
    print(f"  Failed: {FAILED_CONVERSIONS}")
    if tactic_stats:
        print(f"  Tactics covered: {len(tactic_stats)}")

    # Update overall statistics
    TOTAL_SUCCESSFUL += SUCCESSFUL_CONVERSIONS
    TOTAL_FAILED += FAILED_CONVERSIONS

    # Merge tactic stats
    for tactic, count in tactic_stats.items():
        folder_key = f"{rule_folder}/{tactic}"
        overall_stats[folder_key] = count

# Print final statistics
print("\n" + "="*80)
print("OVERALL CONVERSION COMPLETE!")
print("="*80)
print(f"Total files processed: {TOTAL_SUCCESSFUL + TOTAL_FAILED}")
print(f"Total successful conversions: {TOTAL_SUCCESSFUL}")
print(f"Total failed conversions: {TOTAL_FAILED}")
print(f"\nOutput base directory: {OUTPUT_BASE}")
print("\nFolder structure created:")
for rule_folder in RULE_FOLDERS:
    folder_path = os.path.join(OUTPUT_BASE, rule_folder)
    if os.path.exists(folder_path):
        print(f"  {rule_folder}/")
