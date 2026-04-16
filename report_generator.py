import json
import csv
from datetime import datetime
from typing import List, Dict
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ReportGenerator:
    """Generate professional VAPT reports"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
    
    def generate_pdf_report(self, vulnerabilities: List[tuple], 
                           output_path: str = 'vapt_report.pdf') -> bool:
        """Generate professional PDF report"""
        try:
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            elements = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=self.styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1f3339'),
                spaceAfter=6,
                alignment=1
            )
            elements.append(Paragraph("VAPT Assessment Report", title_style))
            elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                                    self.styles['Normal']))
            elements.append(Spacer(1, 0.3*inch))
            
            # Executive Summary
            elements.append(Paragraph("Executive Summary", self.styles['Heading2']))
            total = len(vulnerabilities)
            critical = len([v for v in vulnerabilities if v[3] == 'Critical'])
            high = len([v for v in vulnerabilities if v[3] == 'High'])
            
            summary_data = [
                ['Metric', 'Value'],
                ['Total Vulnerabilities', str(total)],
                ['Critical', str(critical)],
                ['High', str(high)],
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#208a78')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(summary_table)
            elements.append(Spacer(1, 0.3*inch))
            
            # Vulnerabilities Table
            elements.append(Paragraph("Discovered Vulnerabilities", self.styles['Heading2']))
            
            table_data = [['CVE', 'Type', 'Severity', 'EPSS Score', 'Description']]
            for vuln in vulnerabilities[:20]:
                table_data.append([
                    vuln[1],
                    vuln[2],
                    vuln[3],
                    f"{vuln[4]:.2f}",
                    vuln[5][:40] + '...' if len(vuln[5]) > 40 else vuln[5]
                ])
            
            vuln_table = Table(table_data, colWidths=[1*inch, 1.2*inch, 1*inch, 1*inch, 1.8*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#208a78')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey])
            ]))
            elements.append(vuln_table)
            
            # Build PDF
            doc.build(elements)
            return True
        except Exception as e:
            print(f"Error generating PDF: {e}")
            return False
    
    def generate_json_report(self, vulnerabilities: List[tuple],
                            output_path: str = 'findings.json') -> bool:
        """Generate JSON report"""
        try:
            data = {
                'report_date': datetime.now().isoformat(),
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerabilities': []
            }
            
            for vuln in vulnerabilities:
                data['vulnerabilities'].append({
                    'cve': vuln[1],
                    'type': vuln[2],
                    'severity': vuln[3],
                    'epss_score': vuln[4],
                    'description': vuln[5],
                    'affected_url': vuln[6],
                    'target': vuln[7],
                    'status': vuln[8]
                })
            
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error generating JSON: {e}")
            return False
    
    def generate_csv_report(self, vulnerabilities: List[tuple],
                           output_path: str = 'findings.csv') -> bool:
        """Generate CSV report"""
        try:
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['CVE', 'Type', 'Severity', 'EPSS Score', 'Description', 'URL', 'Target', 'Status'])
                
                for vuln in vulnerabilities:
                    writer.writerow([
                        vuln[1], vuln[2], vuln[3], vuln[4],
                        vuln[5], vuln[6], vuln[7], vuln[8]
                    ])
            
            return True
        except Exception as e:
            print(f"Error generating CSV: {e}")
            return False
