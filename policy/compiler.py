import json

from jinja2 import Template


def flatten(l):
    return ",".join(l)


# Read in apps
apps = json.load(open("apps.json", "r"))


def get_app(app):
    return flatten(apps[app]["hosts"]), apps[app]["protocol"], apps[app]["port"]


# Read policy in
policy_data = json.load(open("policy.json", "r"))
with open("iptables", "w") as iptables, open("pan", "w") as pan:
    for policy in policy_data:

        # iptables
        iptables_context = {}

        iptables_context["source"] = policy["source"]
        if policy["destination_type"] == "NETWORK":
            iptables_context["destination"] = flatten(policy["destination"]["hosts"])
            iptables_context["protocol"] = policy["destination"]["protocol"]
            iptables_context["port"] = policy["destination"]["port"]
        elif policy["destination_type"] == "APP":
            (
                iptables_context["destination"],
                iptables_context["protocol"],
                iptables_context["port"],
            ) = get_app(policy["destination"])

        if policy["action"] == "ALLOW":
            iptables_context["action"] = "ALLOW"
        elif policy["action"] == "DENY":
            iptables_context["action"] = "DROP"
        elif isinstance(policy["action"], dict):
            if policy["action"]["type"] == "REDIRECT":
                iptables_context["action"] = "ALLOW"
                iptables_context["destination"] = policy["action"]["address"]

        iptables_rendered_policy = Template(
            open("templates/iptables-simple.j2", "r").read()
        ).render(**iptables_context)

        iptables.write(f"{iptables_rendered_policy}\n")

        # pan
        pan_context = iptables_context

        if policy["destination_type"] == "APP":
            pan_context["app"] = policy["destination"]
        else:
            pan_context["app"] = "application-default"

        if policy["source_type"] == "PRIVATE":
            pan_context["source_zone"] = "trust"
        else:
            pan_context["source_zone"] = "untrust"

        if policy["destination_type"] == "CLOUD":
            pan_context["destination_zone"] = "untrust"
        else:
            pan_context["destination_zone"] = "trust"

        pan_context["action"] = pan_context["action"].lower()

        pan_rendered_policy = Template(
            open("templates/pan-simple.j2", "r").read()
        ).render(**pan_context)

        pan.write(f"{pan_rendered_policy}\n")
