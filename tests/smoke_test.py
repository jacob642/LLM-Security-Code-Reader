import sys
from src.llm_client import detect, explain
from src.prompts import questions
from src.parser import storing


# Run smoke-test samples through both models and compare their results with expected findings.
SQL_INJECTION_CHECK = "is there a sign of any vulnerability"
DETECTION_THRESHOLD = 0.5

SAMPLES = [
    {
        "name": "Vulnerable SQL concatenation",
        "expected": True,
        "code": """\
def get_user(db, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.execute(query)
""",
    },
    {
        "name": "ReDOS",
        "expected": False,
        "code": """\
const express = require('express');
const router = express.Router()


router.get("/tstMe", (req, res) => { 
    var r = /([a-z]+)+$/;

    let match = r.test(req.params.id);
    res.send(match)
    
});


module.exports = router
""",
    },
    {
        "name": "OS Command Injection",
        "expected": False,
        "code": """\
import subprocess

def get_system_uptime():
    result = subprocess.run(
        ["uptime"],
        capture_output=True,
        text=True,
        shell=False
    )
    return result.stdout
""",
    },
    {
        "name": "Different vulnerability: subprocess with user input",
        "expected": False,
        "code": """\

def run_command(user_input):
    subprocess.run("echo " + user_input, shell=True)
""",
    },
    {
        "name": "hashtag testy west ooooooooooooo",
        "expected": True,
        "code": """\
     int _tmain(int argc, _TCHAR* argv[])
{
	char name[64];
	printf("Enter your name: ");
	scanf("%s", name);
	Sanitize(name);
	printf("Welcome, %s!", name);
	return 0;
} }   


""",
    },    
]

# Validate the detector prompt, run all samples through the models, and collect their results.
def main() -> list[dict]:
    results = []
    if SQL_INJECTION_CHECK not in questions: 
        raise KeyError(f"Missing detector prompt: {SQL_INJECTION_CHECK}")

    for sample in SAMPLES:
        code = sample["code"]
        expected = sample["expected"]
        if not isinstance(code, str) or not isinstance(expected, bool):
            raise TypeError("Each sample must have string code and a boolean expectation")

        scores, d3_seconds = detect([SQL_INJECTION_CHECK], code)
        d3_score = scores[SQL_INJECTION_CHECK]
        if not isinstance(d3_score, (int, float)):
            raise TypeError(f"Expected a numeric D3 score, got {type(d3_score).__name__}")

        d3_vulnerable = d3_score >= DETECTION_THRESHOLD
        explanation, qwen_seconds = explain(code, SQL_INJECTION_CHECK)
        agrees = d3_vulnerable == explanation.is_vulnerable
        matches_expectation = d3_vulnerable == expected
        # Store each sample's detection result so it can be reported and checked after the run.
        results.append({
            "name": sample["name"],
            "score": d3_score,
            "expected": expected,
            "d3_vulnerable": d3_vulnerable,
            "passed": matches_expectation,
            "d3_seconds": d3_seconds,
            "qwen_seconds": qwen_seconds,
            "qwen_explanation": explanation.model_dump(),
        })
        # Print the detector, explanation model, timing, and comparison results for this sample.
        print(f"\n{sample['name']}")
        print(f"  Expected SQL injection: {expected}")
        print(f"  D3 score: {d3_score}")
        print(
            f"  D3 says vulnerable (threshold >= {DETECTION_THRESHOLD}): "
            f"{d3_vulnerable}"
        )
        print(f"  Qwen says vulnerable: {explanation.is_vulnerable}")
        print(f"  D3 and Qwen agree: {agrees}")
        print(f"  D3 matches expectation: {matches_expectation}")
        print(f"  D3 took {d3_seconds:.1f}s, Qwen took {qwen_seconds:.1f}s")
        print(f"  Qwen explanation: {explanation.explanation}")
        print(f"  Qwen suggested fix:\n{explanation.fixed_code}")

    print(results)
    return results

# Report failed samples and exit with a failure status when any expectations do not match.
def failure(results: list[dict]) -> None:
    failed = [r for r in results if not r["passed"]]
    for r in failed:
        print(
            f"FAILED: {r['name']} "
            f"(score {r['score']:.3f}, expected {r['expected']}, got {r['d3_vulnerable']})"
        )
    if failed:
        sys.exit(1)
    print("All samples matched expectations")


if __name__ == "__main__":
    results = main()
    storing(results)
    failure(results)