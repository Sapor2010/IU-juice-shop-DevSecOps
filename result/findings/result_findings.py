import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

## path to excel file
excel_file = "result/findings/Findings.xlsx"

## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))
fig.patch.set_alpha(0)

############ Step 1 Read excel File 
data = pd.read_excel(excel_file)

############ Step 2 read rule field and count by security level

## only for debug
print(data)

############ Step 3 visualize 
# Plotting the bar plot
ax = sns.barplot(data=data, palette="viridis")
plt.xlabel('Security Severity Level')
plt.ylabel('Count')
plt.title('Count of Alerts by Security Severity Level')
g = ax.bar_label(ax.containers[0], fmt='%.0f')
## Save result into .svg , .pdf
plt.savefig("result/findings/count_security_tool.svg", format='svg')

plt.show()


