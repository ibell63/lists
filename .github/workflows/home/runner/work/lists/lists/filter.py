import sys
import csv

tif = sys.argv[1]
nrd7 = sys.argv[2]
dga30 = sys.argv[3]
majestic_csv = sys.argv[4]
output = sys.argv[5]

# Load Majestic Million
majestic = set()
with open(majestic_csv, newline="") as f:
    reader = csv.reader(f)
    next(reader)  # skip header
    for row in reader:
        domain = row[2].strip().lower()
        majestic.add(domain)

# Load and combine Hagezi lists
combined = set()

for path in [tif, nrd7, dga30]:
    with open(path) as f:
        for line in f:
            d = line.strip().lower()
            if d:
                combined.add(d)

# Subtract Majestic Million
filtered = [d for d in combined if d not in majestic]

# Write output
with open(output, "w") as f:
    f.write("\n".join(sorted(filtered)))

print("Combined domains:", len(combined))
print("After removing Majestic:", len(filtered))
