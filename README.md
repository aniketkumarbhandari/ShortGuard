<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>URL Shortener Exploit Detection Tool</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
        }

        h1 {
            color: #0073e6;
        }

        ul {
            list-style-type: disc;
            margin-left: 20px;
        }

        code {
            background-color: #f4f4f4;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: monospace;
        }

        .instructions {
            margin-top: 20px;
        }

        .instructions ul {
            list-style-type: decimal;
        }

        .command {
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            margin-top: 10px;
        }
    </style>
</head>

<body>

    <h1>URL Shortener Exploit Detection Tool</h1>

    <p>
        This tool is able to detect if a URL is shortened. Shortened URLs are often used for phishing and several
        malicious purposes. You can detect how safe a URL is to click through the following information:
    </p>

    <ul>
        <li>Identify if a URL is shortened</li>
        <li>Reveal the actual URL of shortened URLs</li>
        <li>Check the blacklisted status of the URL through the VirusTotal public API</li>
        <li>Estimate phishing chances</li>
    </ul>

    <h2>Prerequisites</h2>
    <p>
        Before using this tool, make sure you have installed the latest version of Python.
    </p>

    <h2>Steps to Use This Tool:</h2>
    <div class="instructions">
        <ul>
            <li>Clone the tool to your CLI terminal using <code>git clone</code>.</li>
            <li>Make the tool executable (if needed) using the following command:
                <div class="command">
                    chmod +x filename
                </div>
                Replace <code>filename</code> with the actual name of the saved tool.
            </li>
            <li>Run the tool using:
                <div class="command">
                    ./filename.py
                </div>
                Again, replace <code>filename.py</code> with the name of the tool in <code>.py</code> format.
            </li>
            <li>Paste the URL to be tested and hit enter.</li>
        </ul>
    </div>

</body>

</html>
