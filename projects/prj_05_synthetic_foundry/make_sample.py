"""Deterministically generate the bundled sample customer dataset (400 rows, with PII and real correlations).
PII pools here are intentionally disjoint from the engine's synthetic pools so leak checks are meaningful."""
import csv
import random
from pathlib import Path

FIRST = ["Olivia", "Liam", "Amara", "Noah", "Sofia", "Mateo", "Yuki", "Chen", "Fatima", "Lars", "Priya", "Diego", "Ingrid", "Tariq", "Zoe"]
LAST = ["Hawthorne", "Okafor", "Lindqvist", "Marchetti", "Tanaka", "Abernathy", "Velasquez", "Kowalski", "Nakamura", "Fitzgerald", "Haddad", "Petrov"]
REGIONS = ["north", "south", "east", "west"]


def generate(n: int = 400, seed: int = 7):
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        age = max(18, min(80, int(rng.gauss(41, 12))))
        income = max(15000, rng.gauss(30000 + age * 900, 12000))
        tenure = max(0, int(rng.gauss((age - 18) * 0.25, 2.5)))
        if income > 75000:
            plan = rng.choices(["basic", "pro", "enterprise"], [0.1, 0.5, 0.4])[0]
        elif income > 45000:
            plan = rng.choices(["basic", "pro", "enterprise"], [0.35, 0.55, 0.1])[0]
        else:
            plan = rng.choices(["basic", "pro", "enterprise"], [0.8, 0.19, 0.01])[0]
        churn_p = 0.35 - 0.03 * min(tenure, 8) + (0.1 if plan == "basic" else 0)
        first, last = rng.choice(FIRST), rng.choice(LAST)
        rows.append({
            "customer_id": 1000 + i,
            "full_name": f"{first} {last}",
            "email": f"{first.lower()}.{last.lower()}{rng.randint(10, 99)}@mail-{rng.choice('abcde')}.org",
            "phone": f"({rng.randint(201, 989)}) {rng.randint(200, 999)}-{rng.randint(1000, 9999)}",
            "ssn": f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}",
            "age": age,
            "annual_income": round(income, 2),
            "tenure_years": tenure,
            "region": rng.choices(REGIONS, [0.4, 0.2, 0.25, 0.15])[0],
            "plan": plan,
            "signup_date": f"20{rng.randint(15, 24)}-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}",
            "churned": "true" if rng.random() < max(0.03, churn_p) else "false",
        })
    return rows


def write(dest: Path) -> int:
    rows = generate()
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    dest = Path(__file__).parent / "sample_data" / "customers_sample.csv"
    print(f"wrote {write(dest)} rows -> {dest}")
