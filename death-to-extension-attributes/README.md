# Death to Extension Attributes

## 🚀 Overview
**Death to Extension Attributes** is a repository dedicated to showcasing the stark differences between **Jamf's Extension Attributes** and **Fleet's query capabilities.** The goal is to highlight how Fleet can **save time, improve efficiency, and simplify device management** with single-line queries, compared to the cumbersome multi-line scripts required by Jamf.

If you're tired of managing complex scripts in Jamf and want a more efficient, scalable, and maintainable solution across multiple operating systems, this repository is for you.

---

## ⚡ Why Choose Fleet Queries Over Jamf Extension Attributes?

### 🔍 Simplicity
- **Extension Attributes:** Often requires complex, multi-line scripts to extract system information.
- **Fleet:** Achieves the same results with a single-line SQL query.

### 🌍 Multi-Platform Support
- **Extension Attributes:** Only work on **macOS**, limiting your ability to manage other platforms.
- **Fleet:** Works across **macOS, Windows, Linux, and ChromeOS**, providing a consistent and unified approach to endpoint management.

### ⏳ Efficiency
- **Extension Attributes:** Scripts can be slow, increasing execution time and resource usage on devices.
- **Fleet:** Queries execute efficiently with minimal overhead.

### 🛠️ Maintainability
- **Extension Attributes:** Custom scripts require frequent updates and debugging.
- **Fleet:** Uses standardized SQL queries that are easy to understand and update.

### 📊 Real-Time Insights
- **Extension Attributes:** Data collection is periodic and may not reflect the current system state.
- **Fleet:** Provides real-time, on-demand querying of system data in addition to scheduled queries.

---

## 📖 What's Inside?

This repository includes:

- **Comparative Examples:** Side-by-side comparisons of Extension Attribute scripts vs. Fleet queries.
- **Cross-Platform Use Cases:** How osquery can provide insights across macOS, Windows, and Linux.
- **Fleet Query Examples:** Ready-to-use queries for common IT management tasks.

---

## 🛠 Examples

| Use Case                     | Jamf Extension Attribute (Script) | Fleet query (SQL Query) |
|------------------------------|----------------------------------|--------------------|
| Get macOS Version             | Multi-line shell script         | `SELECT version FROM os_version;` |
| List Installed Applications   | Complex loop & parsing           | `SELECT name, bundle_version FROM apps;` |
| Check Firewall Status         | Custom script                    | `SELECT * FROM alf;` |
| Cross-Platform OS Query       | Not possible                      | `SELECT platform, version FROM os_version;` |

---

## 🌍 Multi-Platform Support

One of Fleet's biggest advantages over Jamf's Extension Attributes is its ability to run on **multiple operating systems,** providing a **unified approach to endpoint visibility.** 

With Fleet, you can write **one query** and apply it across all of your devices, including:

- **macOS** (like Jamf, but more efficient)
- **Windows** (unavailable with Jamf)
- **Linux** (unavailable with Jamf)
- **ChromeOS** (unavailable with Jamf)

This means no more fragmented scripting approaches—just **one language for all platforms.**

---

## 📢 Contributing

We welcome contributions to expand this repository! Feel free to:

- Submit **pull requests** with additional extension attribute vs query examples.
- Report issues or suggest improvements via **GitHub Issues**.
- Share your experiences and feedback with the community.

---

## 📝 License

Use this however you want.

---

### 🚫 Say Goodbye to Extension Attributes, Embrace Simplicity! 🚫
