# AbuseIPDB Win98 IP Tool
# Based on Admiral SYN-ACKbar's AbuseIPDB Bulk Checker 
# Windows 98 style version

# Import necessary libraries
import csv
import requests
import json
import os
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import time
import math
import threading 
import sys
import webbrowser

# Constants
VERSION = "1.0.0"
WINDOW_TITLE = "IP Tool"
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".abuseipdb_config.json")
HELP_URL = "https://www.abuseipdb.com/categories"

def save_api_key(api_key):
    # Save API key to config file
    try:
        config = {"api_key": api_key}
        with open(CONFIG_FILE, 'w') as file:
            json.dump(config, file)
        return True
    except Exception as e:
        print(f"Error saving API key: {str(e)}")
        return False

def load_api_key():
    # Load API key from config
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as file:
                config = json.load(file)
                return config.get("api_key", "")
        return ""
    except Exception as e:
        print(f"Error loading API key: {str(e)}")
        return ""

def check_single_ip(ip_address, api_key, output_box=None, maxAgeInDays=90):
    # Check single ip against AbuseIPDB API
    try:
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip_address}&maxAgeInDays={maxAgeInDays}&verbose=true",
            headers={'Accept': 'application/json', 'Key': api_key}
        )
        if response.status_code == 200:
            data = response.json().get('data', {})
            # Extract data
            ip = data.get('ipAddress', 'N/A')
            score = data.get('abuseConfidenceScore', 'N/A')
            country_code = data.get('countryCode', 'N/A')
            usage_type = data.get('usageType', 'N/A')
            isp = data.get('isp', 'N/A')
            domain = data.get('domain', 'N/A')
            total_reports = data.get('totalReports', 'N/A')
            last_reported = data.get('lastReportedAt', 'N/A')
            
            # Risk level conditions
            risk_level = "Low"
            risk_color = "green"
            if score > 75:
                risk_level = "Critical"
                risk_color = "red"
            elif score > 50:
                risk_level = "High"
                risk_color = "orange"
            elif score > 25:
                risk_level = "Medium"
                risk_color = "yellow"
                
            # More ip info
            is_tor = data.get('isTor', False)
            is_whitelisted = data.get('isWhitelisted', False)
            reports = data.get('reports', [])
            recent_reports = min(len(reports), 10)  # Show 10 most recent reports
              # Format results
            result = f"""
IP Address: {ip}
Abuse Confidence Score: {score}%
Risk Level: {risk_level}
Country Code: {country_code}
Usage Type: {usage_type}
ISP: {isp}
Domain: {domain or 'N/A'}
Total Reports: {total_reports}
Last Reported: {last_reported or 'Never'}
Tor Exit Node: {"Yes" if is_tor else "No"}
Whitelisted: {"Yes" if is_whitelisted else "No"}
"""
            
            # Add the recent reports if available
            if recent_reports > 0:
                result += "\nMost Recent Reports:\n"
                for i in range(recent_reports):
                    report = reports[i]
                    report_date = report.get('reportedAt', 'Unknown')
                    categories = report.get('categories', [])
                    comment = report.get('comment', 'No comment provided')
                    
                    category_names = []
                    if categories:
                        # Map category numbers to names (common categories)
                        category_map = {
                            3: "Fraud",
                            4: "DDoS",
                            5: "Scanning",
                            10: "Web Spam",
                            11: "Email Spam",
                            14: "Brute-Force",
                            15: "Port Scan", 
                            18: "Malware",
                            19: "Phishing",
                            21: "Hacking"
                        }
                        category_names = [category_map.get(cat, f"Category {cat}") for cat in categories]
                    
                    formatted_date = report_date.replace('T', ' ').split('+')[0]
                    
                    report_entry = f"{formatted_date}\n"
                    report_entry += f"Category: {', '.join(category_names)}\n"
                    report_entry += f"Comment: \"{comment}\"\n\n"
                    result += report_entry
                
                if output_box:
                    output_box.delete('1.0', tk.END)
                    output_box.insert(tk.END, result)
                
                # Configure tags for risk levels and reports
                try:
                    # Risk level tags
                    output_box.tag_config("low_risk", foreground="green")
                    output_box.tag_config("medium_risk", foreground="#CC7722")
                    output_box.tag_config("high_risk", foreground="red")
                    output_box.tag_config("critical_risk", foreground="red", font=("Arial", 10, "bold"))
                    
                    # Report section tags
                    output_box.tag_config("report_date", foreground="gray")
                    output_box.tag_config("report_category", foreground="#CC7722")
                    output_box.tag_config("report_comment", foreground="black")
                    
                    # Find and tag the risk level line
                    text_content = output_box.get("1.0", tk.END)
                    lines = text_content.split("\n")
                    
                    # Tag risk level
                    for i, line in enumerate(lines):
                        if "Risk Level:" in line:
                            line_num = i + 1
                            if "Critical" in line:
                                output_box.tag_add("critical_risk", f"{line_num}.0", f"{line_num}.end")
                            elif "High" in line:
                                output_box.tag_add("high_risk", f"{line_num}.0", f"{line_num}.end")
                            elif "Medium" in line:
                                output_box.tag_add("medium_risk", f"{line_num}.0", f"{line_num}.end")
                            else:
                                output_box.tag_add("low_risk", f"{line_num}.0", f"{line_num}.end")
                            break
                    
                    # Tag report sections
                    in_reports_section = False
                    for i, line in enumerate(lines):
                        line_num = i + 1
                        
                        if "Most Recent Reports:" in line:
                            in_reports_section = True
                            continue
                            
                        if in_reports_section and line.strip() and not line.startswith("Most Recent Reports:"):
                            if line.strip().startswith("202"):  # Date lines start with year
                                output_box.tag_add("report_date", f"{line_num}.0", f"{line_num}.end")
                            elif line.strip().startswith("Category:"):
                                output_box.tag_add("report_category", f"{line_num}.0", f"{line_num}.end")
                            elif line.strip().startswith("Comment:"):
                                output_box.tag_add("report_comment", f"{line_num}.0", f"{line_num}.end")
                except Exception as e:
                    print(f"Error applying tags: {str(e)}")  # For debugging
                
            return True, result, score
        else:
            error_msg = f"Error: API returned status code {response.status_code}"
            if output_box:
                output_box.delete('1.0', tk.END)
                output_box.insert(tk.END, error_msg)
            return False, error_msg, None
            
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        if output_box:
            output_box.delete('1.0', tk.END)
            output_box.insert(tk.END, error_msg)
        return False, error_msg, None

def bulk_check(csv_path, api_key, export_path, progress=None, output_box=None, max_age_days=90):
    # Bulk check ips against AbuseIPDB API
    start_time = time.time()
    results = []
    # Create a temp file in the output directory
    json_temp_path = os.path.join(os.path.dirname(export_path), 'aipdbulkchecktempfile.json')  #

    try:
        with open(csv_path, 'r') as file:
            csv_reader = csv.reader(file)
            total_rows = sum(1 for row in csv_reader)  # Calculate row sum in the CSV file
            file.seek(0)  # Reset file pointer to beginning

            for i, row in enumerate(csv_reader):
                if not row:  # Skip empty rows
                    continue
                    
                ip = row[0].strip()  # Extract ips from the row and remove whitespace
                
                if not ip:  # Skip empty ips
                    continue

                # Update UI before making request
                status_msg = f"Processing {i + 1} of {total_rows}: {ip}..."
                if output_box and progress:
                    progress['value'] = (i + 1) / total_rows * 100
                    output_box.delete('1.0', tk.END)
                    output_box.insert(tk.END, status_msg)
                    if hasattr(progress, 'master') and hasattr(progress.master, 'update_idletasks'):
                        progress.master.update_idletasks()

                # Send API request to check ips
                response = requests.get(
                    f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose=true",
                    headers={'Accept': 'application/json', 'Key': api_key}
                )

                if response.status_code == 200:  # If the API request was successful
                    # Store response
                    results.append(response.json())
                    
                    # Write to temp file
                    with open(json_temp_path, 'a') as json_file:
                        json_file.write(json.dumps(response.json()) + "\n")
                    
                    status_msg = f"Processing {i + 1} of {total_rows}: {ip} - Success"
                else:  # If API request was not successful
                    status_msg = f"Processing {i + 1} of {total_rows}: {ip} - Error: {response.status_code}"

                # Update UI after request
                if output_box and progress:
                    output_box.delete('1.0', tk.END)
                    output_box.insert(tk.END, status_msg)
                    if hasattr(progress, 'master') and hasattr(progress.master, 'update_idletasks'):
                        progress.master.update_idletasks()

                # Add a small delay to avoid hitting API rate limits
                time.sleep(0.5)

        # Process results and write to CSV
        with open(json_temp_path, 'r') as json_file, open(export_path, 'w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file)
            
            # Write the header row
            csv_writer.writerow([
                'IP Address', 'Abuse Confidence Score', 'Risk Level', 'Country Code', 
                'Usage Type', 'ISP', 'Domain', 'Total Reports', 'Last Reported', 
                'Is TOR', 'Is Whitelisted'
            ])
            
            # Process each IP check result
            for line in json_file:
                response_json = json.loads(line)
                data = response_json.get('data', {})
                
                # Extract the relevant data
                ip = data.get('ipAddress', 'N/A')
                score = data.get('abuseConfidenceScore', 'N/A')
                country_code = data.get('countryCode', 'N/A')
                usage_type = data.get('usageType', 'N/A')
                isp = data.get('isp', 'N/A')
                domain = data.get('domain', 'N/A')
                total_reports = data.get('totalReports', 'N/A')
                last_reported = data.get('lastReportedAt', 'N/A')
                is_tor = 'Yes' if data.get('isTor', False) else 'No'
                is_whitelisted = 'Yes' if data.get('isWhitelisted', False) else 'No'
                
                # Determine risk level
                risk_level = "Low"
                if score != 'N/A':
                    if int(score) > 75:
                        risk_level = "Critical"
                    elif int(score) > 50:
                        risk_level = "High"
                    elif int(score) > 25:
                        risk_level = "Medium"
                
                # Write the data to the CSV file
                csv_writer.writerow([
                    ip, score, risk_level, country_code, usage_type, isp, domain, 
                    total_reports, last_reported, is_tor, is_whitelisted
                ])

        # Clean up temp file
        if os.path.exists(json_temp_path):
            os.remove(json_temp_path)
            
        # Calculate statistics
        end_time = time.time()
        elapsed_time = end_time - start_time
        elapsed_minutes, elapsed_seconds = divmod(elapsed_time, 60)
        elapsed_minutes = math.floor(elapsed_minutes)
        elapsed_seconds = round(elapsed_seconds, 1)
        
        # Calculate average time
        avg_time_per_ip = elapsed_time / total_rows if total_rows > 0 else 0
        avg_time_per_ip = round(avg_time_per_ip, 1)
        
        completion_msg = f"Processing complete! Checked {total_rows} IPs in {elapsed_minutes}m {elapsed_seconds}s (avg: {avg_time_per_ip}s per IP)"
        
        if output_box:
            output_box.delete('1.0', tk.END)
            output_box.insert(tk.END, completion_msg)

        return True, completion_msg
        
    except Exception as e:
        error_msg = f"Error: {str(e)}"
        if output_box:
            output_box.delete('1.0', tk.END)
            output_box.insert(tk.END, error_msg)
        return False, error_msg

def create_help_window(parent):
    # Create a help window with instructions
    help_window = tk.Toplevel(parent)
    help_window.title("IP Tool Help")
    help_window.geometry("600x500")
    help_window.configure(bg='#C0C0C0')
    
    help_text = """
IP Tool Help Guide

1. Getting Started:
   - First, enter your AbuseIPDB API key (get one at https://www.abuseipdb.com/account/api)
   - Your API key will be saved locally for future use
   - You can check individual IPs or process a CSV file containing multiple IPs

2. Single IP Check:
   - Enter the IP address in the input field
   - Click "Check IP" to get the abuse report
   - Results show abuse confidence score, location, and recent abuse reports
   - Risk level is color-coded (Low, Medium, High, Critical)

3. Bulk Check:
   - Prepare a CSV file with IPs in the first column
   - Select input file and output location
   - Click "Start Bulk Processing" to process all IPs
   - Progress will be shown in the status bar

4. Understanding Results:
   - Abuse Confidence Score: 0-100% likelihood of being malicious
   - Risk Level: Based on the abuse score (Low, Medium, High, Critical)
   - Reports: Shows number of abuse reports and details
   - TOR Exit Node: Indicates if IP is a known TOR exit node
   
5. Tips:
   - API has rate limits (1,000 requests per day for free accounts)
   - For bulk checks, consider using a paid API plan
   - Bulk check saves results to a CSV file for further analysis

For more information, visit https://www.abuseipdb.com
    """
    
    help_scrollbar = ttk.Scrollbar(help_window)
    help_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    help_box = tk.Text(help_window, yscrollcommand=help_scrollbar.set, bg='#FFFFFF', padx=10, pady=10)
    help_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    help_box.insert(tk.END, help_text)
    help_box.config(state=tk.DISABLED)  # Make it read-only
    
    help_scrollbar.config(command=help_box.yview)
    
    button_frame = tk.Frame(help_window, bg='#C0C0C0')
    button_frame.pack(fill=tk.X, pady=10)
    
    visit_site_btn = tk.Button(button_frame, text="Visit AbuseIPDB Categories", relief="raised", bd=2,
                             command=lambda: webbrowser.open(HELP_URL))
    visit_site_btn.pack(side=tk.LEFT, padx=10)
    
    close_button = tk.Button(button_frame, text="Close", command=help_window.destroy, relief="raised", bd=2)
    close_button.pack(side=tk.RIGHT, padx=10)
    
    # Center the window relative to parent
    help_window.transient(parent)
    help_window.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - help_window.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - help_window.winfo_height()) // 2
    help_window.geometry(f"+{x}+{y}")
    
    help_window.focus_set()
    help_window.grab_set()

def create_shortcut(target_path=None):
    # Create a Windows shortcut for easy application launching
    if not sys.platform.startswith('win'):
        return False, "This feature is only available on Windows"
        
    if target_path is None:
        target_path = os.path.abspath(sys.argv[0])
    
    try:
        try:
            import win32com.client
        except ImportError:
            return False, "Missing required package: pywin32. Please install it with 'pip install pywin32'"
        
        # Get desktop path
        desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
        shortcut_path = os.path.join(desktop, f"{WINDOW_TITLE}.lnk")
        
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target_path
        shortcut.WorkingDirectory = os.path.dirname(target_path)
        shortcut.Description = f"{WINDOW_TITLE} - AbuseIPDB Checker"
        shortcut.save()
        return True, "Shortcut created successfully"
    except Exception as e:
        return False, f"Error creating shortcut: {str(e)}"

def create_tkinter_gui():
    # Create a Windows 98 style GUI
    root = tk.Tk()
    root.title(WINDOW_TITLE)
    root.geometry("550x700")
    root.minsize(500, 650)  # Set minimum window size
    
    try:
        root.tk_setPalette(background='#C0C0C0')
        style = ttk.Style()
        style.theme_use('clam')  # Similar to Win98
        style.configure("TButton", relief="raised", borderwidth=2)
        style.configure("TProgressbar", troughcolor='white', background='navy')
        style.configure("TNotebook", background='#C0C0C0')
        style.configure("TNotebook.Tab", padding=[10, 4], background='#C0C0C0')
    except:
        pass  # Fallback default style if theme fails
    
    # Main content
    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
    
    # API Key frame with save option
    api_key_frame = tk.Frame(main_frame)
    api_key_frame.pack(fill=tk.X, pady=5)
    
    api_key_label = tk.Label(api_key_frame, text="API Key:")
    api_key_label.pack(side=tk.LEFT, pady=(5, 0))
    
    # Store API key
    api_key_var = tk.StringVar()
    api_key = tk.Entry(api_key_frame, width=40, relief="sunken", bd=2, textvariable=api_key_var, show="•")
    api_key.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5), pady=5)
    
    # Load saved API key if available
    saved_key = load_api_key()
    if saved_key:
        api_key_var.set(saved_key)
    
    # Function to toggle API key visibility
    def toggle_api_key_visibility():
        if api_key.cget('show') == '•':
            api_key.config(show='')
            show_hide_btn.config(text='Hide')
        else:
            api_key.config(show='•')
            show_hide_btn.config(text='Show')
    
    show_hide_btn = tk.Button(api_key_frame, text="Show", relief="raised", bd=2, 
                             command=toggle_api_key_visibility, width=6)
    show_hide_btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    # Function to save API key
    def save_key():
        key = api_key_var.get().strip()
        if key:
            if save_api_key(key):
                messagebox.showinfo("Success", "API Key saved successfully")
            else:
                messagebox.showerror("Error", "Failed to save API Key")
        else:
            messagebox.showwarning("Warning", "Please enter an API Key to save")
    
    save_key_btn = tk.Button(api_key_frame, text="Save", relief="raised", bd=2, 
                           command=save_key, width=6)
    save_key_btn.pack(side=tk.LEFT, padx=5, pady=5)
    
    # Create notebook (tabbed interface)
    notebook = ttk.Notebook(main_frame)
    notebook.pack(fill=tk.BOTH, expand=True, pady=10)
    
    # === SINGLE CHECK TAB (first tab) ===
    single_tab = tk.Frame(notebook)
    notebook.add(single_tab, text="Single IP Check")
    
    # Single IP input
    single_ip_label = tk.Label(single_tab, text="IP Address:")
    single_ip_label.pack(anchor=tk.W, pady=(10, 0))
    single_ip_entry = tk.Entry(single_tab, width=50, relief="sunken", bd=2)
    single_ip_entry.pack(fill=tk.X, pady=5)
    
    # Single IP output
    single_output_label = tk.Label(single_tab, text="Results:")
    single_output_label.pack(anchor=tk.W, pady=(10, 0))
    single_output_frame = tk.Frame(single_tab)
    single_output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
    single_output_box = tk.Text(single_output_frame, height=15, relief="sunken", bd=2)
    single_output_box.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
    
    single_output_scroll = ttk.Scrollbar(single_output_frame, command=single_output_box.yview)
    single_output_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    single_output_box.configure(yscrollcommand=single_output_scroll.set)
    
    # Button frame
    single_button_frame = tk.Frame(single_tab)
    single_button_frame.pack(fill=tk.X, pady=10)
    
    # Single check button
    single_check_button = tk.Button(single_button_frame, text="Check IP", height=2, width=15, relief="raised", bd=2)
    single_check_button.pack(side=tk.LEFT, padx=(0, 10))
    
    # Copy to clipboard button
    def copy_to_clipboard():
        root.clipboard_clear()
        root.clipboard_append(single_output_box.get("1.0", tk.END))
        status_label.config(text="Results copied to clipboard")
        root.after(3000, lambda: status_label.config(text="Ready"))
    
    copy_button = tk.Button(single_button_frame, text="Copy Results", height=2, width=15, 
                          relief="raised", bd=2, command=copy_to_clipboard)
    copy_button.pack(side=tk.LEFT)
    
    # === BULK CHECK TAB (second tab) ===
    bulk_tab = tk.Frame(notebook)
    notebook.add(bulk_tab, text="Bulk Check")
    
    # Input file
    input_label = tk.Label(bulk_tab, text="CSV Input File:")
    input_label.pack(anchor=tk.W, pady=(10, 0))
    input_frame = tk.Frame(bulk_tab)
    input_frame.pack(fill=tk.X, pady=5)
    input_path = tk.Entry(input_frame, width=40, relief="sunken", bd=2)
    input_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def browse_input():
        filename = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            input_path.delete(0, tk.END)
            input_path.insert(0, filename)
    
    input_browse = tk.Button(input_frame, text="Browse...", relief="raised", bd=2, command=browse_input)
    input_browse.pack(side=tk.RIGHT, padx=(5, 0))
    
    # Output file
    output_label = tk.Label(bulk_tab, text="CSV Output File:")
    output_label.pack(anchor=tk.W, pady=(10, 0))
    output_frame = tk.Frame(bulk_tab)
    output_frame.pack(fill=tk.X, pady=5)
    output_path = tk.Entry(output_frame, width=40, relief="sunken", bd=2)
    output_path.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def browse_output():
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if filename:
            output_path.delete(0, tk.END)
            output_path.insert(0, filename)
    
    output_browse = tk.Button(output_frame, text="Browse...", relief="raised", bd=2, command=browse_output)
    output_browse.pack(side=tk.RIGHT, padx=(5, 0))
    
    # Max age setting
    max_age_frame = tk.Frame(bulk_tab)
    max_age_frame.pack(fill=tk.X, pady=5)
    max_age_label = tk.Label(max_age_frame, text="Max Age (days):")
    max_age_label.pack(side=tk.LEFT)
    max_age_var = tk.StringVar(value="90")
    max_age_entry = tk.Entry(max_age_frame, width=5, textvariable=max_age_var)
    max_age_entry.pack(side=tk.LEFT, padx=5)
    
    # Progress bar and bulk output
    progress_label = tk.Label(bulk_tab, text="Progress:")
    progress_label.pack(anchor=tk.W, pady=(20, 0))
    progress = ttk.Progressbar(bulk_tab, orient=tk.HORIZONTAL, length=100, mode='determinate')
    progress.pack(fill=tk.X, pady=5)
    
    bulk_output_label = tk.Label(bulk_tab, text="Status:")
    bulk_output_label.pack(anchor=tk.W, pady=(10, 0))
    bulk_output_frame = tk.Frame(bulk_tab)
    bulk_output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    
    bulk_output_box = tk.Text(bulk_output_frame, height=10, relief="sunken", bd=2)
    bulk_output_box.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
    
    bulk_output_scroll = ttk.Scrollbar(bulk_output_frame, command=bulk_output_box.yview)
    bulk_output_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    bulk_output_box.configure(yscrollcommand=bulk_output_scroll.set)
    
    # Bulk Start button
    bulk_start_button = tk.Button(bulk_tab, text="Start Bulk Processing", height=2, relief="raised", bd=2)
    bulk_start_button.pack(pady=10)
    
    # Status bar - Win98 style
    status_frame = tk.Frame(root, bd=1, relief=tk.SUNKEN)
    status_frame.pack(side=tk.BOTTOM, fill=tk.X)
    status_label = tk.Label(status_frame, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
    status_label.pack(fill=tk.X)
    
    def start_bulk_process():
        if not api_key.get():
            bulk_output_box.delete('1.0', tk.END)
            bulk_output_box.insert(tk.END, "ERROR: Please enter your API key")
            return
        
        if not input_path.get():
            bulk_output_box.delete('1.0', tk.END)
            bulk_output_box.insert(tk.END, "ERROR: Please select an input file")
            return
        
        if not output_path.get():
            bulk_output_box.delete('1.0', tk.END)
            bulk_output_box.insert(tk.END, "ERROR: Please select an output file")
            return
            
        try:
            max_age = int(max_age_var.get())
            if max_age < 1:
                raise ValueError("Max age must be positive")
        except:
            bulk_output_box.delete('1.0', tk.END)
            bulk_output_box.insert(tk.END, "ERROR: Max Age must be a valid number (default: 90)")
            max_age_var.set("90")
            return
        
        bulk_output_box.delete('1.0', tk.END)
        bulk_output_box.insert(tk.END, "Processing started...\n")
        status_label.config(text="Processing...")
        
        # Disable start button while processing
        bulk_start_button.config(state=tk.DISABLED)
        
        def process_thread():
            success, message = bulk_check(
                input_path.get(), api_key_var.get(), output_path.get(), 
                progress, bulk_output_box, max_age
            )
            
            # Re-enable button after processing
            root.after(0, lambda: bulk_start_button.config(state=tk.NORMAL))
            
            if success:
                status_label.config(text="Ready")
                messagebox.showinfo("Complete", message)
            else:
                status_label.config(text="Error")
                messagebox.showerror("Error", message)
        
        # Start in a separate thread to prevent GUI freezing
        threading.Thread(target=process_thread, daemon=True).start()
    
    bulk_start_button.config(command=start_bulk_process)
    
    def start_single_check():
        if not api_key_var.get():
            single_output_box.delete('1.0', tk.END)
            single_output_box.insert(tk.END, "ERROR: Please enter your API key")
            return
        
        ip_address = single_ip_entry.get().strip()
        if not ip_address:
            single_output_box.delete('1.0', tk.END)
            single_output_box.insert(tk.END, "ERROR: Please enter an IP address")
            return
        
        status_label.config(text="Checking IP...")
        single_check_button.config(state=tk.DISABLED)
        single_output_box.delete('1.0', tk.END)
        single_output_box.insert(tk.END, f"Checking {ip_address}...\n")
        
        def single_check_thread():
            success, result, score = check_single_ip(ip_address, api_key_var.get(), single_output_box)
            
            # Re-enable button after processing
            root.after(0, lambda: single_check_button.config(state=tk.NORMAL))
            
            if success:
                status_label.config(text="Ready")
            else:
                status_label.config(text="Error")
        
        # Start in a separate thread to prevent GUI freezing
        threading.Thread(target=single_check_thread, daemon=True).start()
    
    single_check_button.config(command=start_single_check)
    
    # Button bar for help and about
    button_bar = tk.Frame(main_frame)
    button_bar.pack(fill=tk.X, pady=5)
      # Create shortcut button
    def make_shortcut():
        success, message = create_shortcut()
        if success:
            messagebox.showinfo("Success", f"Desktop shortcut for {WINDOW_TITLE} created successfully")
        else:
            messagebox.showerror("Error", message)
    
    shortcut_button = tk.Button(button_bar, text="Create Desktop Shortcut", 
                              relief="raised", bd=2, command=make_shortcut)
    shortcut_button.pack(side=tk.LEFT, pady=5)
    
    # Help button
    help_button = tk.Button(button_bar, text="Help", relief="raised", bd=2,
                          command=lambda: create_help_window(root))
    help_button.pack(side=tk.RIGHT, padx=(5, 0), pady=5)
    
    # About button
    def show_about():
        messagebox.showinfo("About", f"{WINDOW_TITLE} v{VERSION}\n\nA Windows-styled tool for checking IP addresses against the AbuseIPDB database.\n\nVisit the AbuseIPDB website at https://www.abuseipdb.com")
    
    about_button = tk.Button(button_bar, text="About", relief="raised", bd=2, command=show_about)
    about_button.pack(side=tk.RIGHT, pady=5)
    
    # Bind Enter key to perform IP check when in entry field
    single_ip_entry.bind("<Return>", lambda event: start_single_check())
    
    # Start with first tab selected
    notebook.select(0)
    
    return root

# Main entry point
if __name__ == "__main__":
    # Use traditional Tkinter GUI
    root = create_tkinter_gui()
    root.mainloop()
