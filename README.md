<h1>Phishing Email Analysis</h1>

 ### [YouTube Demonstration (Coming Soon)](https://youtu.be/)

<h2>Description</h2>
This project consists of an overview of the core concepts of Phishing email analysis and reporting. As I am wanting to gain practical experience and competence in this required skill, I have created this playbook and guide with explanations to help fellow future cyber security professionals wanting to do the same. My aim is to use publicaly submitted phishing emails for analysis, reporting and training.
<br />


<h2>Languages and Utilities Used</h2>

- <b> Header + AuthN: Google Admin Toolbox (Messageheader), MxToolbox, Microsoft 365 Message Trace, Linux whois/dig/nslookup.
- <b> URL + Domain OSINT: VirusTotal, URLhaus, PhishTank, Talos Intelligence, AbuseIPDB, GreyNoise, urlscan.io.
- <b> Attachment Static:
  •	Office: oleid, olevba, mraptor (oletools)
  •	PDFs: pdfid, pdf-parser.py
  •	Archives: 7z, binwalk
- <b> Executables: pefile, die/detect-it-easy, strings, yara
- <b> Sandbox Dynamic: ANY.RUN, Hybrid Analysis, Joe Sandbox (if licensed), Intezer.
- <b> Decoding/Parsing: CyberChef.
- <b> Case Mgmt/Automation (optional): TheHive + Cortex analyzers; MISP for intel storage.
- <b> Follow org policy before submitting customer data to third party services.
</b>

<h2>Environments Used </h2>

- <b>Windows 11 , Ubuntu VM </b> (21H2)

<h2>Scope and Definitions:</h2>

- <b>	In-scope: Phishing, malware delivery, BEC, spoofing, brand abuse.
- <b> Artifacts: Raw email (EML/MSG), headers, body, URLs, attachments, sender metadata, infrastructure indicators.
- <b>	Outcomes: Benign, Spam, Phish, Malware, BEC, Social Engineering, Graymail.
</b>

<h2>Preconditions and Safety:</h2>

- <b>	Use an isolated VM for analysis. No corporate creds. No internet proxy bypass.
- <b>	Never open attachments on bare metal or production workstation.
- <b>	Work from a case folder: INC-<YYYYMMDD>-<ticket#>/ with subfolders: email/, headers/, urls/, attachments/, reports/, screenshots/.
- <b>	Compute and record hashes for all files: SHA256, SHA1, MD5.
  
- <b>Template:
- <b>INC-20250825-1234/
- <b>email/original.eml
- <b>headers/original_headers.txt
- <b>attachments/<filename>
- <b>urls/urls.csv
- <b> reports/virustotal.txt
- <b> screenshots/*.png
</b>

<h2>Workflow Overview:</h2>

- <b>Intake → Header/AuthN → Body/Content → URLs → Attachments → Infrastructure → Impact → Verdict → Response
- <b>Each phase has clear pass/fail gates and outputs.
</b>

<h2>Intake and Ticket Hygiene:</h2>

- <b>Capture source: reporter, mailbox, gateway alert, or automated feed.
- <b>Export raw email as EML/MSG. Save to case folder.
- <b>Record: reporter, time received, subject, sender, recipients, attachments count, links count.
- <b>Initial triage tags: phishing-suspected, malware-suspected, bec-suspected, spoofing.
- <b>Output: Clean case folder and basic metadata noted in ticket.
 </b>

<h2>5) Header and Authentication Checks:</h2>
- <b>1.Extract full headers to headers/original_headers.txt.
- <b>2.Review Received chain top→bottom for anomalies: private IPs, time skew, hops in unexpected regions.
- <b>3.Parse key fields: From, Reply-To, Return-Path, Message-ID domain alignment.
- <b>4.Check SPF result and domain alignment.
- <b>5.Check DKIM result, selector, and signing domain.
- <b>6.Check DMARC policy and alignment (pass/fail/quarantine/reject).
- <b>7.Compare envelope-from vs header-from vs Return-Path.
- <b>Red flags:
- <b>•SPF/DKIM fail with header-from domain of interest.
- <b>•Message-ID domain mismatch with sender.
- <b>•Reply-To different from From to free-mail domain.
- <b>•Inconsistent Received path or forged headers.
- <b>Output: AuthN summary with pass/fail and alignment notes saved to ticket.
 </b>

<h2>6) Body and Content Review:</h2>
- <b>1.	Open in plain text or safe viewer. Do not enable images or external content.
- <b>2.	Extract: all URLs, visible and obfuscated; phone numbers; payment instructions; language indicators (urgency, threats, gift cards).
- <b>3.	Note brand impersonation and lures.
- <b>4.	Capture screenshots of key cues.
- <b>Output: urls/urls.csv with url, context, visible_text, location_in_email and content notes.
 </b>
 _______________________________________
<h2>7) URL and Domain Analysis:</h2>
- <b>1.	Normalize URLs: defang → refang → canonicalize.
- <b>2.	Resolve final destinations safely using urlscan.io or sandbox preview. Avoid direct browsing.
- <b>3.	Check domain and hosting age (whois), registrar, and DNS changes.
- <b>4.	OSINT reputation: VirusTotal, URLhaus, PhishTank, Talos, AbuseIPDB, GreyNoise.
- <b>5.	Look for homoglyphs, subdomain tricks, misspellings.
- <b>6.	If a login page, check if it proxies to real brand or hosts look alike kit.
- <b>Output: URL risk table with evidence links and screenshots.
</b>
 _____________________________________
<h2>8) Attachment Analysis:</h2>
- <b>Safe handling: detach in VM, compute hashes, do static first.
<h2>8.1 Static triage:</h2>
- <b>•	Office: run oleid and olevba to detect macros/auto open, IOCs, URLs.
- <b>•	PDFs: pdfid for triggers, pdf-parser.py to extract JS/launch actions.
- <b>•	Archives: list contents, test passwords from email context if provided.
- <b>•	Executables: strings, pefile, packer detection; check imports; compute hashes; query VirusTotal.
<h2>8.2 Dynamic analysis:</h2>
- <b>•	Run in sandbox with internet simulation. Observe DNS, HTTP, process tree, dropped files, persistence keys.
- <b>•	Extract additional IOCs and add to case.
- <b>Output: Attachment report with hashes, tool outputs, sandbox verdict, and extracted IOCs.
________________________________________
<h2>9) Infrastructure and Actor Signal:</h2>s
- <b>•	Collate IOCs: IPs, domains, URLs, hashes, emails, ASNs.
- <b>•	Pivot: shared SSL certs, hosting provider, registrar email, name servers.
- <b>•	Check for campaign overlap in MISP, open intel feeds, and previous tickets.
- <b>•	Determine likely intent: credentials theft, malware delivery, BEC.
- <b>Output: IOC bundle in CSV and STIX/MISP (if available).
</b>
 _______________________________________
<h2>10) Impact Assessment:</h2>
- <b>•	Did the recipient interact? Clicked link, entered creds, opened attachment, executed macro, replied?
- <b>•	Check proxy, EDR, and email logs for beaconing or downloads.
- <b>•	Search SIEM for the same subject/sender/URL to find other recipients.
- <b>•	If creds may be exposed, identify accounts and systems at risk.
- <b>Output: Affected user list and immediate containment needs.
 </b>
________________________________________
<h2>11) Verdict and Confidence:</h2>
- <b>Use a simple matrix:
- <b>Category	Indicators	Confidence
- <b>Phish	Brand impersonation + credential harvest page or known bad URL	High/Med
- <b>Malware	Malicious attachment behavior or sandbox detonation	High/Med
- <b>BEC	Payment/urgency + reply to switch + no links/attachments	Med
- <b>Spam/Benign	Marketing or legit sender with poor hygiene	Low
- <b>Record confidence and list decisive evidence.
 </b>
________________________________________
<h2>12) Response Actions (choose as applicable):</h2>
- <b>•	Containment: Quarantine original message, purge from all mailboxes, block sender/domain, block URLs/domains at email gateway, DNS, and proxy.
- <b>•	User: Notify recipients, advise if clicked, guide password reset and MFA review.
- <b>•	Credentials: Force reset, revoke sessions, check OAuth consents.
- <b>•	Endpoint: EDR sweep for dropped files, persistence, C2 domains.
- <b>•	Reporting: Submit to brand abuse portals or take down where applicable.
- <b>•	Intel: Add IOCs to blocklists and MISP.
- <b>•	Lessons: Update mail filters, add detections for new lures/templates.
- <b>Output: Actions logged with timestamps and systems touched.
 </b>
________________________________________
<h2>13) Documentation Checklist (copy into ticket):</h2>
- <b>•	Source and reporter
- <b>•	Header auth results (SPF/DKIM/DMARC + alignment)
- <b>•	Key header anomalies
- <b>•	URL list and reputation
- <b>•	Attachment hashes + static/dynamic results
- <b>•	IOC set (IPs, domains, URLs, hashes, emails)
- <b>•	Impact on users/endpoints
- <b>•	Verdict + confidence
- <b>•	Response actions taken
- <b>•	Artifacts attached (files, screenshots, reports)
 </b>
________________________________________
<h2>14) MITRE ATT&CK Mapping:</h2>
- <b>•	T1566: Phishing (delivery vector)
- <b>•	T1204: User Execution (macro/open)
- <b>•	T1059: Command and Scripting Interpreter (macro → PowerShell)
- <b>•	T1056/T1556: Credential Collection/Modification (phish kits)
- <b>•	T1105/T1071: Exfiltration/Command and Control over Web/HTTPS
- <b>•	T1568: Dynamic Resolution (DNS)
- <b>•	T1567: Exfiltration to Cloud Storage (if observed)
<h2>Defensive notes (mitigations):</h2>
- <b>•	Email authentication (SPF, DKIM, DMARC).
- <b>•	Attachment sandboxing.
- <b>•	URL rewriting and time of click protection.
- <b>•	Macro restrictions and ASR rules.
- <b>•	MFA and conditional access.
- <b>•	User awareness with targeted education from real cases.
 </b>
________________________________________
<h2>15) Quick Commands and Snippets:</h2>
- <b>Hashes
- <b>•	Linux: sha256sum <file>
- <b>•	PowerShell: Get-FileHash -Algorithm SHA256 <file>
- <b>Header pull (Outlook desktop)
- <b>•	File → Properties → Internet headers → copy to headers/*.txt
- <b>Regex: extract URLs
- <b>https?://[\w\-\._~:/?#\[\]@!$&'()*+,;=%]+
- <b>Whois/DNS
- <b>•	whois example.com
- <b>•	dig A example.com +short
- <b>•	dig NS example.com +short
 </b>
________________________________________
<h2>16) False Positives to Watch:</h2>
- <b>•	Third party senders failing SPF due to forwarding.
- <b>•	DKIM body canonicalization breaking on reformat.
- <b>•	Legit password reset or invoice emails from new SaaS vendors.
- <b>•	Archived or encrypted attachments sent legitimately by partners.
 </b>
________________________________________
<h2>17) Metrics for Continuous Improvement:</h2>
- <b>•	Time from intake to verdict.
- <b>•	% of cases with full header analysis completed.
- <b>•	Recurrence rate of same lure/domain.
- <b>•	Block efficacy of new rules (pre vs post).
 </b>
________________________________________
<h2>18) Appendices:</h2>
- <b>A) Triage Form Template
- <b>Ticket ID:
- <b>Reporter:
- <b>Subject:
- <b>Sender / Return-Path / Reply-To:
- <b>SPF/DKIM/DMARC results:
- <b>Header anomalies:
- <b>URLs extracted:
- <b>Attachments (name, type, size, hashes):
- <b>Sandbox results:
- <b>IOCs:
- <b>User interaction observed:
- <b>Verdict + Confidence:
- <b>Actions taken:
- <b>Notes:
- <b>B) IOC CSV Headers
- <b>type,value,first_seen,last_seen,source,notes
- <b>C) Playbook Exit Criteria
- <b>Case is complete when: verdict logged, actions executed, artifacts attached, IOCs distributed, and ticket QA passed.
 </b>
________________________________________
 <h2>Optional Automation Ideas:</h2>
- <b>•	Auto extract headers and compute alignment checks.
- <b>•	Auto defang/refang and reputation lookups via APIs.
- <b>•	Auto enrichment in ticket with VT/urlscan/URLhaus summaries.
- <b>•	One click purge across tenant for confirmed phish.
</b>






<p align="center">
Launch the utility: <br/>
<img src="https://i.imgur.com/62TgaWL.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
