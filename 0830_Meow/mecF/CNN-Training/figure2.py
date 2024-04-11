import matplotlib.pyplot as plt

# 每月雨量数据
monthly_rainfall = {
    "January": 50,
    "February": 45,
    "March": 60,
    "April": 55,
    "May": 70,
    "June": 80,
    "July": 90,
    "August": 85,
    "September": 75,
    "October": 65,
    "November": 55,
    "December": 60
}

# 提取月份和对应的雨量数据
months = list(monthly_rainfall.keys())
rainfall_values = list(monthly_rainfall.values())

# 繪製每月雨量長條圖
plt.bar(months, rainfall_values, color='blue')

# 添加標籤和標題
plt.xlabel('Month')
plt.ylabel('Rainfall (mm)')
plt.title('Monthly Rainfall')

# 顯示繪製的圖表
plt.xticks(rotation=45)
plt.grid(True)
plt.show()