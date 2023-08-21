import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt
from datetime import date, datetime
import matplotlib.dates as mdates
import matplotlib.ticker as ticker

## path to excel file
excel_file = "result/runtime/summary_security.xlsx"


## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))

############ Step 1 Read excel File 
data = pd.read_excel(excel_file)


# ############ Step 2 visualize 
# Create the barplot using seaborn
ax = sns.barplot(data=data, palette="viridis")
# label each column
for i in ax.containers:
    ax.bar_label(i, padding=10, fmt='%.1f')
plt.title("Execution Times")
plt.ylabel("Time (seconds)")
plt.xlabel("Tools")
# ## Save result into .svg , .pdf
plt.savefig("result/runtime/avarage_duration_summery_security.svg", format='svg')


plt.show()

## only for debug
print(data)


data.to_excel('result/runtime/result_security.xlsx')
