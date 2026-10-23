# AI usage: dsc26-cyb-w02

## Tools

I mainly used Claude to work on the threat model and the Python checker. I used ChatGPT in the final stage to understand the threat scoring, review the new threats, troubleshoot issues, and complete the AI usage documentation.

## What AI got wrong

Some AI guidance was based on an earlier state of the threat model. I checked the current YAML file and ran the checker again to verify the results before accepting the guidance.

## In my own words

1. A data store has no Spoofing threat in STRIDE per element because Spoofing targets an identity, not the data store itself. The threat applies to the user or process whose identity an attacker tries to impersonate.

2. I would fix T38 first because unauthorized access to the feature store could expose customers personal data. Protecting this information is important for customer privacy and security.

