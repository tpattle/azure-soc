## Building a Mini Honeynet with SOC Capabilities in Microsoft Azure
If you'd like to check out the in-depth project breakdown, check out my article: <br /> [Building a SOC and Honeynet in Microsoft Azure: A Hands-On Guide to Threat
Detection and Incident Response](https://www.linkedin.com/pulse/building-soc-honeynet-microsoft-azure-hands-on-guide-threat-pattle-i6jbf)

<p align="center">
  <img src="https://github.com/user-attachments/assets/ed9106ba-e4a6-495e-a7e0-21a8c11e0133" alt="project diagram">
</p>

### Introduction
In this project, I constructed a mini honeynet in Microsoft Azure, integrating various resources and logging sources into a Log Analytics workspace. This workspace was then leveraged by Microsoft Sentinel to build attack maps, trigger alerts, and create incidents based on live attack data. 

The project followed a structured approach:
1. **Metrics Collection in an Insecure Environment**: I initially measured security metrics over a 24-hour period in an exposed environment to capture baseline data on attacks.
2. **Environment Hardening and Re-Testing**: I then applied a series of security controls, after which I measured the metrics over another 24-hour period to observe the impact of these controls.

### Key Metrics Tracked
Before and after applying security measures, the following metrics were monitored:
- **SecurityEvent** (Windows Event Logs)
- **Syslog** (Linux Event Logs)
- **SecurityAlert** (Triggered Alerts in Log Analytics)
- **SecurityIncident** (Incidents created by Sentinel)
- **AzureNetworkAnalytics_CL** (Allowed Malicious Flows into the Honeynet)

### Architecture Summary
The architecture of this mini honeynet is comprised of:
- **Virtual Network (VNet)**
- **Network Security Group (NSG)**
- **Virtual Machines** (2 Windows, 1 Linux)
- **Log Analytics Workspace**
- **Azure Key Vault**
- **Azure Storage Account**
- **Microsoft Sentinel**

#### *Before Hardening*:
- All resources were exposed to the internet with public endpoints. 
- NSGs and built-in firewalls on VMs were left open, maximizing visibility to simulate a highly vulnerable environment.

  <p align="center">
  <img width="400" src="https://github.com/user-attachments/assets/95651db0-05ad-4e03-94a7-cd5da7b5030e" alt="before hardening">
</p>

#### *After Hardening*:
- NSGs were reconfigured to block all traffic except from my admin workstation.
- All other resources were further protected using built-in firewalls and Private Endpoints, removing public exposure.

  <p align="center">
  <img width="400" src="https://github.com/user-attachments/assets/2fe5d9c7-d621-4e23-9a70-bfd46d759727" alt="after hardening">
</p>

### Results and Metrics Comparison

**Attack Maps Before Hardening**:
- **NSG Allowed Inbound Malicious Flows**
- **Linux Syslog Authentication Failures**
- **Windows RDP/SMB Authentication Failures**

| **Metric**                  | **Count (Before Hardening)** | **Count (After Hardening)** |
|-----------------------------|------------------------------|-----------------------------|
| SecurityEvent               | 35,623                       | 18,728                      |
| Syslog                      | 12,374                       | 25                          |
| SecurityIncident            | 276                          | 0                           |
| AzureNetworkAnalytics_CL    | 2,793                        | 0                           |

### Conclusion
This project successfully demonstrated the impact of SOC monitoring and incident response in a cloud environment by integrating Microsoft Sentinel to track real-time security events. By implementing hardening measures, I achieved a drastic reduction in security events and incidents, highlighting the effectiveness of robust security controls.

**Note**: In a highly utilized production environment, additional events or alerts may be generated due to increased user activity post-hardening, making ongoing monitoring essential.
