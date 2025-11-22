# Lessons Learned

Documentation of problems encountered and how they were solved.

## Why This Matters

Troubleshooting skills are highly valued by employers. Documenting failures shows:
- Problem-solving ability
- Persistence
- Growth mindset

## Format

Each entry should include:
- **Problem:** What went wrong
- **Symptoms:** How you noticed the issue
- **Investigation:** Steps taken to diagnose
- **Solution:** What fixed it
- **Prevention:** How to avoid in the future

## Example Entry

### 2025-11-21: Kali Couldn't Reach Domain Controller

**Problem:** Kali on different subnet than lab network

**Symptoms:** `nmap` couldn't find DC, ping failed

**Investigation:** Checked `ip a`, found Kali on 192.168.8.x while DC on 192.168.10.x

**Solution:** Changed VMware network adapter to VMnet10, set static IP

**Prevention:** Always verify network adapter settings match lab network before starting
