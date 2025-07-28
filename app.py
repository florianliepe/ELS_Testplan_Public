
import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter
import io

st.set_page_config(page_title="Cutover Test Dashboard", layout="wide")

st.title("🚀 Cutover Test Dashboard")
st.markdown("Track and visualize test execution status across locations and categories.")

uploaded_file = st.file_uploader("Upload Test Data (Excel)", type=["xlsx"])
if uploaded_file:
    df = pd.read_excel(uploaded_file, sheet_name="Test Data")

    st.sidebar.header("🔍 Filters")
    selected_category = st.sidebar.multiselect("Test Category", options=df["Test Category"].unique(), default=df["Test Category"].unique())
    selected_location = st.sidebar.multiselect("Location", options=df["Location"].unique(), default=df["Location"].unique())
    selected_status = st.sidebar.multiselect("Status", options=df["Status"].unique(), default=df["Status"].unique())

    filtered_df = df[
        df["Test Category"].isin(selected_category) &
        df["Location"].isin(selected_location) &
        df["Status"].isin(selected_status)
    ]

    st.markdown(f"### 📋 Filtered Test Cases: {len(filtered_df)}")
    st.dataframe(filtered_df)

    # Status by Category
    st.markdown("### 📊 Test Execution Status by Category")
    status_pivot = filtered_df.pivot_table(index='Test Category', columns='Status', aggfunc='size', fill_value=0)
    fig1, ax1 = plt.subplots()
    status_pivot.plot(kind='bar', stacked=True, colormap='tab20', ax=ax1)
    plt.ylabel("Number of Test Cases")
    plt.xlabel("Test Category")
    plt.xticks(rotation=45)
    st.pyplot(fig1)

    # Location Completion
    st.markdown("### 🌍 Location-wise Completion (%)")
    location_status = filtered_df.groupby("Location")["Status"].value_counts().unstack().fillna(0)
    location_status["% Complete"] = (location_status.get("Pass", 0) / location_status.sum(axis=1)) * 100
    fig2, ax2 = plt.subplots()
    sns.heatmap(location_status[["% Complete"]], annot=True, fmt=".0f", cmap="YlGn", cbar_kws={'format': PercentFormatter()}, ax=ax2)
    st.pyplot(fig2)

    # Status Pie Chart
    st.markdown("### 🥧 Test Case Summary by Status")
    status_counts = filtered_df["Status"].value_counts()
    fig3, ax3 = plt.subplots()
    ax3.pie(status_counts, labels=status_counts.index, autopct='%1.1f%%', colors=sns.color_palette('Set2'))
    st.pyplot(fig3)

    # Timeline Table
    st.markdown("### 📅 Upcoming Test Timeline")
    st.dataframe(filtered_df.sort_values("Planned Date")[["Planned Date", "Test Case ID", "Test Category", "Location", "Owner", "Status"]])
