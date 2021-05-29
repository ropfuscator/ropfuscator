#!/usr/bin/env python3

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

    mean_df = df.groupby('Tigress Sample').mean()

    min_t = 15
    delta_t = 15
    max_t = 1200  # from experiments

    print(
        "Slowest sample (in solving time [s]) in increments of 15 secs starting from 15 secs:")
    for t in range(min_t, max_t, delta_t):
        ranged_df = mean_df[mean_df['Execution Time [s]'].between(
            t, t + delta_t)]

        if ranged_df.size > 0:
            print(
                f"{t} < t <= {t + delta_t} [s]:", end="")
            print(
                f"\t{ranged_df.idxmax().values[0]}\t{ranged_df.max().values[0]:0.2f}")


if __name__ == "__main__":
    main()
