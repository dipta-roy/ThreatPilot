import os
from pathlib import Path

def update_inits(root_dir):
    for root, dirs, files in os.walk(root_dir):
        if '__init__.py' in files:
            init_file = Path(root) / '__init__.py'
            
            # Find all .py files in the directory
            py_files = []
            for f in files:
                if f.endswith('.py') and f != '__init__.py':
                    py_files.append(f[:-3])
            
            with open(init_file, 'r', encoding='utf-8') as f:
                content = f.read()
                
            if '__all__' not in content:
                all_str = '\n__all__ = [\n'
                for pf in sorted(py_files):
                    all_str += f'    "{pf}",\n'
                all_str += ']\n'
                
                with open(init_file, 'a', encoding='utf-8') as f:
                    f.write(all_str)

update_inits(r'f:\ThreatPilot\threatpilot')
