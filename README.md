# SIEM-Lite

### What is this?

This is a simple command-line tool I built to make sense of security logs. It's a lightweight SIEM (Security Information and Event Management) engine. It pulls in logs from different places (like your web server and Linux auth logs), lines them all up in order by time, and then flags anything that looks suspicious based on a set of rules.

### What can it do?

  * **Reads different log types:** Right now, it understands SSH `auth.log` and Apache `access.log` formats.
  * **Creates a Master Timeline:** It merges everything into a single, chronological timeline so you can easily see the sequence of events.
  * **Finds Bad Stuff:** Using a `rules.json` file, it can spot simple things like someone trying to access `/etc/passwd` on a web server, or more complex patterns like a brute-force SSH attack.
  * **Built to be expanded:** I designed it so adding new parsers for other log types (like CSVs or Windows logs) would be pretty straightforward.

### How to Get it Running

**1. Clone the Code**
First, you'll need to grab the files from GitHub.

```bash
git clone https://github.com/your-username/siem-lite.git
cd siem-lite
```

**2. Create a Virtual Environment**
It's always best to keep project stuff separate.

```bash
# Create the venv
python3 -m venv venv

# Activate it
source venv/bin/activate
```

**3. Install It**
This will install the tool and any other libraries it needs to run.

```bash
pip install -e .
```

**4. Set Up Your Config**
I've included a `config.example.json` file to show you the format. Just copy it to get started.

```bash
cp config.example.json config.json
```

Make sure to open up `config.json` and change the file paths to wherever your log files are.

**5. Run It\!**
That's it. Just run the command and it'll do its thing.

```bash
siem-lite
```

You'll see the full timeline of events and any alerts that were triggered printed right to your terminal. Hope you find it useful\!
