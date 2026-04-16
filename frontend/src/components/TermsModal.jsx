import { useState } from 'react';
import './TermsModal.css';
import logoImg from '../assets/Havoc Sec LOGO red white.png';

export default function TermsModal({ user, onAccept }) {
  const [checked, setChecked] = useState(false);
  const [exiting, setExiting] = useState(false);

  const handleAccept = () => {
    if (!checked) return;
    // Persist acceptance
    const key = `havoc_tos_accepted_${user?.email || 'default'}`;
    localStorage.setItem(key, 'true');
    // Animate out then notify parent
    setExiting(true);
    setTimeout(() => onAccept(), 420);
  };

  return (
    <div className={`terms-overlay ${exiting ? 'terms-exit' : ''}`}>
      <div className={`terms-card ${exiting ? 'terms-card-exit' : ''}`}>

        {/* Logo */}
        <div className="terms-logo-row">
          <img src={logoImg} alt="Havoc Security" className="terms-logo" />
        </div>

        {/* Title */}
        <h2 className="terms-title">Terms &amp; Conditions</h2>
        <p className="terms-subtitle">Please read and accept before continuing · www.havocsecurity.in</p>

        {/* Scrollable disclaimer content */}
        <div className="terms-body">

          {/* Section 1 */}
          <div className="terms-section">
            <span className="terms-icon">📋</span>
            <div>
              <h4>Acceptance of Terms</h4>
              <p>
                Welcome to Havoc Security! By accessing or using our website
                (<strong>www.havocsecurity.in</strong>), services, or digital content, you agree
                to follow these Terms of Use. By visiting or using Havoc Security, you accept
                these Terms fully. If you do not agree with any part of these terms, please
                refrain from using the site or services. Continued use constitutes your
                acceptance. Havoc Security may update these terms periodically, and your
                continued use after changes implies acceptance of the updated terms.
              </p>
            </div>
          </div>

          {/* Section 2 */}
          <div className="terms-section">
            <span className="terms-icon">⚠️</span>
            <div>
              <h4>Authorized Scanning Only</h4>
              <p>
                Havoc Security runs active security scans including port scanning, vulnerability
                detection, fuzzing, and injection testing. These techniques can be <strong>illegal</strong> if
                performed against systems you do not own or do not have <strong>explicit written
                authorization</strong> to test. Only use this platform to scan websites, applications,
                and infrastructure that you personally own or for which you have received
                documented permission from the owner. Unauthorized scanning of third-party
                assets is <strong>strictly prohibited</strong>.
              </p>
            </div>
          </div>

          {/* Section 3 */}
          <div className="terms-section">
            <span className="terms-icon">🌐</span>
            <div>
              <h4>Use of Website &amp; Services</h4>
              <p>
                Havoc Security grants you a limited, non-exclusive, and non-transferable right
                to access our website and services for personal or professional purposes. You
                agree not to misuse the site, attempt unauthorized access, or interfere with its
                functionality. All content, including text, images, graphics, interface designs,
                and software, remains the intellectual property of Havoc Security unless stated
                otherwise.
              </p>
            </div>
          </div>

          {/* Section 4 */}
          <div className="terms-section">
            <span className="terms-icon">🔒</span>
            <div>
              <h4>Intellectual Property</h4>
              <p>
                All content, designs, logos, and resources provided by Havoc Security are
                protected under copyright, trademark, and other intellectual property laws. You
                may not copy, distribute, or create derivative works without explicit
                authorization. Our branding, visuals, and proprietary AI technology represent
                years of strategy and development. Unauthorized use undermines this effort
                and may result in legal consequences.
              </p>
            </div>
          </div>

          {/* Section 5 */}
          <div className="terms-section">
            <span className="terms-icon">📤</span>
            <div>
              <h4>User-Generated Content</h4>
              <p>
                When you submit targets, feedback, or materials to Havoc Security, you grant us
                permission to use, adapt, and integrate the content for internal or project
                purposes. You confirm that you have the rights and authorizations to any systems
                or materials submitted for scanning and that they do not infringe on third-party
                rights or violate applicable laws. Havoc Security is not responsible for
                unauthorized submissions or disputes arising from user content.
              </p>
            </div>
          </div>

          {/* Section 6 */}
          <div className="terms-section">
            <span className="terms-icon">⚖️</span>
            <div>
              <h4>Limitation of Liability</h4>
              <p>
                Havoc Security strives for accuracy and reliability across all services, resources,
                and AI-driven remediation guidance. However, we cannot guarantee uninterrupted
                access, complete accuracy, or suitability for every purpose. <strong>Use of our
                website and services is at your own risk.</strong> Havoc Security, its team, and
                partners are <strong>not liable</strong> for direct, indirect, incidental, or consequential
                damages resulting from access to or use of the site. This includes technical
                failures, data loss, or errors in vulnerability reporting. You assume full
                responsibility for all scanning activity performed through your account.
              </p>
            </div>
          </div>

          {/* Section 7 */}
          <div className="terms-section">
            <span className="terms-icon">📜</span>
            <div>
              <h4>Legal Compliance &amp; Governing Law</h4>
              <p>
                By using Havoc Security, you agree to comply with all applicable local, national,
                and international laws governing computer security testing, penetration testing,
                and data privacy — including but not limited to the Computer Fraud and Abuse Act
                (CFAA), GDPR, and the <strong>Information Technology Act, 2000 (India)</strong>.
                These Terms of Use are governed by the laws of India. Any disputes will be
                subject to the jurisdiction of Indian courts. Users agree to resolve conflicts
                respectfully and in good faith.
              </p>
            </div>
          </div>

          {/* Section 8 */}
          <div className="terms-section">
            <span className="terms-icon">✉️</span>
            <div>
              <h4>Contact</h4>
              <p>
                For questions, clarifications, or concerns regarding these terms, reach out
                to our team at <strong>info@havocsecurity.in</strong>. We prioritize
                transparency and timely responses. Havoc Security aims for collaboration,
                clarity, and trust in every interaction.
              </p>
            </div>
          </div>
        </div>

        {/* Checkbox */}
        <label className="terms-checkbox-row" onClick={() => setChecked(c => !c)}>
          <div className={`terms-custom-check ${checked ? 'checked' : ''}`}>
            {checked && (
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                <path d="M2.5 6L5 8.5L9.5 3.5" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            )}
          </div>
          <span>
            I have read and agree to the Terms &amp; Conditions of Havoc Security. I confirm
            that I will only scan websites and systems I own or have explicit authorization
            to test, and I accept full responsibility for my actions on this platform.
          </span>
        </label>

        {/* Accept button */}
        <button
          className={`terms-accept-btn ${checked ? 'active' : ''}`}
          disabled={!checked}
          onClick={handleAccept}
        >
          Accept &amp; Agree
        </button>
      </div>
    </div>
  );
}
