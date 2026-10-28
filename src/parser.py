import json

# Store the completed smoke-test results in a JSON file.
def storing(results):
    with open("json_prompt.json", "w", encoding="utf-8") as output_file:
        json.dump(results, output_file, indent=2, ensure_ascii=False)