# Results

We evaluated the generation of sample crack-mes through Tigress' "RandomFuns" pass. There are various settings that enable the user to generate a variety of different functions thus modifying the effectiveness of symbolic execution engines when trying to solve them.

We did a quick experiment by modifying the loop iterations in each of the random functions calculations. The samples are appended with a number that represents the number of iterations. Successively, we solved these challenges with an angr script that looks if the correct output is produces by these challenges and compared the execution time. We have picked samples with different execution times to present different scenarios. The results of these experiments are in the file `angr_solve_times.csv`.