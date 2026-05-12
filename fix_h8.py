import re

with open('core/executor/src/lib.rs', 'r') as f:
    content = f.read()

# Pattern to match: let var_name = AccountAddress::from_hex_literal(&format!("0x{}", var)).unwrap_or(AccountAddress::ZERO);
pattern = re.compile(r'(\s*)let\s+(\w+)\s*=\s*AccountAddress::from_hex_literal\(&format!\("0x\{\}",\s*([^)]+)\)\)\.unwrap_or\(AccountAddress::ZERO\);')

def replacer(match):
    indent = match.group(1)
    var_name = match.group(2)
    expr = match.group(3)
    return f'{indent}let {var_name} = match AccountAddress::from_hex_literal(&format!("0x{{}}", {expr})) {{\n{indent}    Ok(addr) => addr,\n{indent}    Err(_) => {{\n{indent}        println!("❌ Invalid address format: {{}}", {expr});\n{indent}        return None;\n{indent}    }}\n{indent}}};'

new_content = pattern.sub(replacer, content)

with open('core/executor/src/lib.rs', 'w') as f:
    f.write(new_content)

print("H-8 fixed!")
