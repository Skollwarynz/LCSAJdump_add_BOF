import json
import re

with open('unified_weights_v5.json', 'r') as f:
    best = json.load(f)

with open('lcsajdump/core/config.py', 'r') as f:
    config_content = f.read()

for arch, data in best.items():
    # Update scoring_weights
    sw_str = json.dumps(data["scoring_weights"], indent=10)
    sw_pattern = r'("scoring_weights": \{[^}]+\})'
    
    # We need to replace only the specific arch block.
    # A simple regex for each arch block
    arch_pattern = re.compile(rf'"{arch}": {{(.*?)("scoring_weights": \{{[^\}}]+\}})(.*?)("search_params": \{{[^\}}]+\}})', re.DOTALL)
    
    match = arch_pattern.search(config_content)
    if match:
        new_sw = f'"scoring_weights": {sw_str.strip()}'
        sp_str = json.dumps(data["search_params"], indent=10)
        new_sp = f'"search_params": {sp_str.strip()}'
        
        # Replace scoring weights
        updated_arch_block = re.sub(r'"scoring_weights": \{[^}]+\}', new_sw, match.group(0))
        # Replace search params
        updated_arch_block = re.sub(r'"search_params": \{[^}]+\}', new_sp, updated_arch_block)
        
        config_content = config_content.replace(match.group(0), updated_arch_block)

with open('lcsajdump/core/config.py', 'w') as f:
    f.write(config_content)
print("Updated config.py successfully.")
