import matplotlib.pyplot as plt
from matplotlib.patches import Patch
import numpy as np

# Stages of the Evolutionary Prototype Model
stages = [
    "Requirement Gathering",
    "Requirement Analysis",
    "Prototype Development",
    "User Evaluation",
    "Prototype Refinement",
    "Testing & Validation",
    "Final Delivery"
]

# Timeline data in months (0 = June)
# Each tuple is (start_month, duration_in_months)
planned_data = [
    (0, 1),  # Requirement Gathering (June)
    (1, 1),  # Requirement Analysis (July)
    (2, 2),  # Prototype Development (Aug-Sep)
    (4, 1),  # User Evaluation (Oct)
    (5, 2),  # Prototype Refinement (Nov-Dec)
    (7, 1),  # Testing & Validation (Jan)
    (8, 1)   # Final Delivery (Feb)
]

actual_data = [
    (0, 0.75),  # Requirement Gathering (June 1st to 3rd week)
    (0.75, 0.5), # Requirement Analysis (June 4th week to July 2nd week)
    (1.25, 2.75), # Prototype Development (July 2nd week to end of October)
    (4, 1),      # User Evaluation (completed in October)
    (5, 2.25),   # Prototype Refinement (Nov, Dec, first week of Jan)
    (7.25, 1),   # Testing & Validation (2nd week of Jan to 1st week of Feb)
    (8.25, 0.75) # Final Delivery (remaining 3 weeks of Feb)
]

# Month labels for the x-axis, now including March
months = ["June", "July", "August", "September", "October", "November", "December", "January", "February", "March"]

# Reverse lists for plotting from top to bottom
stages = stages[::-1]
planned_data = planned_data[::-1]
actual_data = actual_data[::-1]

# Create the plot
fig, ax = plt.subplots(figsize=(12, 7))

# Define y-positions for the bars
y_positions = np.arange(len(stages))

# Plot bars
for i, stage in enumerate(stages):
    # Plot planned bar
    planned_start, planned_duration = planned_data[i]
    ax.barh(y_positions[i] + 0.2, planned_duration, left=planned_start,
            height=0.4, edgecolor="black", facecolor="white")

    # Plot actual bar
    actual_start, actual_duration = actual_data[i]
    ax.barh(y_positions[i] - 0.2, actual_duration, left=actual_start,
            height=0.4, color="black", alpha=0.8)

# Set labels and title
ax.set_xlabel("Timeline (Months)")
ax.set_title("Evolutionary Prototype Model: Planned vs. Actual Timeline")
ax.set_yticks(y_positions)
ax.set_yticklabels(stages)

# Configure x-axis with month labels
ax.set_xticks(np.arange(len(months)))
ax.set_xticklabels(months)

# Adjust the x-axis limit to show March
ax.set_xlim(-0.5, len(months) - 0.5)

# Create legend
legend_elements = [
    Patch(facecolor='white', edgecolor='black', label='Planned'),
    Patch(facecolor='black', label='Actual')
]
ax.legend(handles=legend_elements, loc='upper right')

# Add grid lines
ax.grid(axis="x", linestyle="--", alpha=0.5)

plt.tight_layout()
plt.show()
 just till the september end should be there actual working is done so just modified it
