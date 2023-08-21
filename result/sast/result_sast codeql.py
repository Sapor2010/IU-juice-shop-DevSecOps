import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

## path to json file
json_file = "result/sast/response.json"

## Styling the Plot and split axes
sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))
fig.patch.set_alpha(0)

############ Step 1 Read json File 
dat = pd.read_json(json_file)

############ Step 2 read rule field and count by security level
severity_counts = dat['rule'].apply(lambda x: x['severity'])
severity_counts = severity_counts.value_counts()

tags_count = dat['rule'].apply(lambda x: x['tags'])
tags_count = tags_count.value_counts()

## only for debug
print(tags_count)
severity_counts.to_excel('result/sast/result_codeql.xlsx')

############ Step 3 visualize 
# Plotting the bar plot
plt.bar(severity_counts.index, severity_counts.values, color=['red', 'orange', 'green'])
plt.xlabel('Security Severity Level')
plt.ylabel('Count')
plt.title('Count of Alerts by Security Severity Level')
g = ax.bar_label(ax.containers[0], fmt='%.0f')
## Save result into .svg , .pdf
plt.savefig("result/sast/codeql_countsecuritylevel.svg", format='svg')
plt.show()

