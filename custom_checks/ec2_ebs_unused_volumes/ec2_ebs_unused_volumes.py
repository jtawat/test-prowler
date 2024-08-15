from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_ebs_unused_volumes(Check):
    """ec2_ebs_unused_volumes checks for unused EBS volumes"""

    def execute(self):
        findings = []

        for volume in ec2_client.volumes:
            report = Check_Report_AWS(self.metadata())
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            report.resource_tags = volume.tags

            report.status = 'FAIL'

            print(volume)

            if volume.state == "in-use":
                report.status = "PASS"
                report.status_extended = f"EBS volume {volume.id} is in use."
            else:
                report.status = "FAIL"
                report.status_extended = f"EBS volume {volume.id} is unused."

            findings.append(report)

        return findings
