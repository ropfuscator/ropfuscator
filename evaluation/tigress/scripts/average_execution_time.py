import sys
from pathlib import Path
import pandas


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <benchmark.csv>")
        return

    if not Path(sys.argv[1]).exists():
        print("The file does not exist!")
        return

    with open(sys.argv[1], "r") as f:
        df = pandas.read_csv(f, names=["Tigress Sample", "Execution Time [s]"])
    
    print(df.groupby('Tigress Sample').mean())


if __name__ == "__main__":
    main()
