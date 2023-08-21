import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

## path to json file
excel_file = "result/dast/dast_summary.xlsx"

# ## Styling the Plot and split axes
# sns.set_style("whitegrid")
fig, ax = plt.subplots(nrows=1, ncols=1, figsize=(10,5))
# fig.patch.set_alpha(0)

# ############ Step 1 Read excel File 
df = pd.read_excel(excel_file, index_col=0)

# ############ Step 2 visualize

# ## only for debug
# print(data)

# Erste Grafik: Risk Level auf der x-Achse und summierte Werte auf der y-Achse
ax = plt.figure(figsize=(10, 6))
ax = sns.barplot(x=df.index, y=df.sum(axis=1))
g = ax.bar_label(ax.containers[0], fmt='%.0f', padding=5)
plt.xlabel('Risk Level')
plt.ylabel('Summierte Werte')
plt.title('Summierte Werte nach Risk Level')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("result/dast/dast_risklevel.svg", format='svg')


# Zweites Diagramm: Datum vs. Risk Level Summe
df_date = df.iloc[:, 1:]
sum_by_date = df_date.sum(axis=0)
ax = plt.figure(figsize=(10, 6))
ax = sns.barplot(x=df_date.columns, y=sum_by_date.values)
g = ax.bar_label(ax.containers[0], fmt='%.0f', padding=5)
plt.xlabel('Datum')
plt.ylabel('Summe')
plt.title('Datum vs. Risk Level Summe')
plt.xticks(rotation=45)
plt.tight_layout()

## Save result into .svg , .pdf
plt.savefig("result/dast/dast_summary.svg", format='svg')


plt.show()

