# ipinfo-wazuh
Integration IPInfo x Wazuh

It's necessarry create rule on Wazuh based in GeoLocation.

But, with Filebeat GeoLocation it is not possible make this rules.

The GeoIP data is added to the events in a higher level of the stack, that's why you can see it in the final events but it can't be used to trigger alerts.

To resolve this problem, I created a integration with IPInfo API to consult GeoIP and create rules based in this.

Create your account in IPInfo (https://ipinfo.io/), copy your token and modifify on script

![image](https://github.com/marcus-ar/ipinfo-wazuh/assets/87987392/e76900ba-63f9-45c7-b2f6-13c66d1116da)

1) Create the custom-ipinfo.py on /var/ossec/integration

2) Set the permissions 

  chmod 750 /var/ossec/integrations/custom-ipinfo.py

  chown root:wazuh /var/ossec/integrations/custom-ipinfo.py

3) Create ossec.conf config

4) Create rules on Wazuh Manager

I used the rule 81622 (Fortigate: VPN user connected.) But you can use your necessary rule.



