# Import the necessary classes
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client

class ec2_ebs_general_purpose_ssd(Check):
    """ec2_ebs_general_purpose_ssd checks if EBS volumes are using gp2/gp3"""

    def execute(self):
        findings = []

        # Iterate through all EBS volumes
        for volume in ec2_client.volumes:
            report = Check_Report_AWS(self.metadata())

            # Set the required fields for the report
            report.region = volume.region
            report.resource_id = volume.id
            report.resource_arn = volume.arn
            report.resource_tags = volume.tags

            report.status = 'FAIL'

            print(volume)

            # Check if the volume type is gp2 or gp3
            if volume.volume_type in ["gp2", "gp3"]:
                report.status = "PASS"
                report.status_extended = f"EBS volume {volume.id} is using {volume.volume_type} (General Purpose SSD)."
            else:
                report.status = "FAIL"
                report.status_extended = f"EBS volume {volume.id} is not using General Purpose SSD (gp2/gp3). It is using {volume.volume_type}."

            findings.append(report)

        return findings
