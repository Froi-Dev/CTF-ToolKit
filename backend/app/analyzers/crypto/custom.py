from __future__ import annotations

import ast
from typing import Literal
from pydantic import BaseModel
from app.core.analyzers import BaseAnalyzer

class CustomAnalyzeInput(BaseModel):
    source_code: str

class CustomFinding(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: float
    description: str

class CustomAnalyzeResponse(BaseModel):
    analyzer: Literal["custom_analyzer"] = "custom_analyzer"
    category: Literal["crypto"] = "crypto"
    findings: list[CustomFinding]
    extracted_constants: dict[str, str]
    proposed_solver: str | None

class CustomEncryptionAnalyzer(BaseAnalyzer[CustomAnalyzeInput, CustomAnalyzeResponse]):
    name = "custom_analyzer"
    category = "crypto"

    def supports(self, value: object) -> bool:
        return isinstance(value, CustomAnalyzeInput)

    def analyze(self, value: CustomAnalyzeInput) -> CustomAnalyzeResponse:
        findings = []
        constants = {}
        
        try:
            tree = ast.parse(value.source_code)
        except SyntaxError as e:
            findings.append(CustomFinding(
                title="Syntax Error",
                severity="low",
                confidence=1.0,
                description=f"Could not parse Python source code: {e}"
            ))
            return CustomAnalyzeResponse(findings=findings, extracted_constants={}, proposed_solver=None)

        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Extract constants
                        if isinstance(node.value, ast.Constant):
                            constants[target.id] = repr(node.value.value)

        if constants:
            findings.append(CustomFinding(
                title="Extracted Constants",
                severity="info",
                confidence=1.0,
                description=f"Found {len(constants)} constants in the source code."
            ))

        # Generate a naive proposed solver skeleton
        solver = "def solve():\n"
        for k, v in constants.items():
            solver += f"    {k} = {v}\n"
        solver += "    # Implement inverse operations here based on the original script\n"
        solver += "    pass\n\nif __name__ == '__main__':\n    solve()\n"

        return CustomAnalyzeResponse(
            findings=findings,
            extracted_constants=constants,
            proposed_solver=solver
        )
