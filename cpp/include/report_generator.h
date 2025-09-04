#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include "common.h"
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <fstream>

namespace nsa {

class ReportGenerator {
public:
    ReportGenerator();
    ~ReportGenerator();

    // Initialize report generator
    void initialize(const Config& config);
    
    // Generate comprehensive security report
    bool generate_security_report(const std::string& filename,
                                 const Statistics& stats,
                                 const std::vector<Threat>& threats,
                                 const std::vector<Threat>& anomalies);
    
    // Generate threat report
    bool generate_threat_report(const std::string& filename,
                               const std::vector<Threat>& threats);
    
    // Generate anomaly report
    bool generate_anomaly_report(const std::string& filename,
                                const std::vector<Threat>& anomalies);
    
    // Generate statistical report
    bool generate_statistical_report(const std::string& filename,
                                    const Statistics& stats);
    
    // Generate real-time alert
    std::string generate_alert(const Threat& threat);
    
    // Generate summary report
    std::string generate_summary(const Statistics& stats,
                                const std::vector<Threat>& threats,
                                const std::vector<Threat>& anomalies);
    
    // Set report format
    void set_format(const std::string& format); // "html", "json", "xml", "txt"
    
    // Set report template
    void set_template(const std::string& template_path);
    
    // Enable/disable report sections
    void enable_executive_summary(bool enabled);
    void enable_detailed_analysis(bool enabled);
    void enable_recommendations(bool enabled);
    void enable_appendix(bool enabled);

private:
    // Configuration
    Config config_;
    std::string report_format_;
    std::string template_path_;
    
    // Report options
    bool executive_summary_enabled_;
    bool detailed_analysis_enabled_;
    bool recommendations_enabled_;
    bool appendix_enabled_;
    
    // Report templates
    struct ReportTemplate {
        std::string html_template;
        std::string json_template;
        std::string xml_template;
        std::string text_template;
    };
    
    ReportTemplate templates_;
    
    // Format-specific generation
    bool generate_html_report(const std::string& filename,
                             const Statistics& stats,
                             const std::vector<Threat>& threats,
                             const std::vector<Threat>& anomalies);
    
    bool generate_json_report(const std::string& filename,
                             const Statistics& stats,
                             const std::vector<Threat>& threats,
                             const std::vector<Threat>& anomalies);
    
    bool generate_xml_report(const std::string& filename,
                            const Statistics& stats,
                            const std::vector<Threat>& threats,
                            const std::vector<Threat>& anomalies);
    
    bool generate_text_report(const std::string& filename,
                             const Statistics& stats,
                             const std::vector<Threat>& threats,
                             const std::vector<Threat>& anomalies);
    
    // Report sections
    std::string generate_executive_summary(const Statistics& stats,
                                          const std::vector<Threat>& threats,
                                          const std::vector<Threat>& anomalies);
    
    std::string generate_threat_summary(const std::vector<Threat>& threats);
    std::string generate_anomaly_summary(const std::vector<Threat>& anomalies);
    std::string generate_statistical_summary(const Statistics& stats);
    
    std::string generate_detailed_threat_analysis(const std::vector<Threat>& threats);
    std::string generate_detailed_anomaly_analysis(const std::vector<Threat>& anomalies);
    std::string generate_detailed_statistical_analysis(const Statistics& stats);
    
    std::string generate_recommendations(const std::vector<Threat>& threats,
                                        const std::vector<Threat>& anomalies);
    
    std::string generate_appendix(const Statistics& stats,
                                 const std::vector<Threat>& threats,
                                 const std::vector<Threat>& anomalies);
    
    // HTML generation helpers
    std::string generate_html_header(const std::string& title);
    std::string generate_html_footer();
    std::string generate_html_table(const std::vector<std::string>& headers,
                                   const std::vector<std::vector<std::string>>& rows);
    std::string generate_html_chart(const std::string& chart_id,
                                   const std::string& chart_type,
                                   const std::map<std::string, uint64_t>& data);
    
    // JSON generation helpers
    std::string generate_json_object(const std::map<std::string, std::string>& data);
    std::string generate_json_array(const std::vector<std::string>& items);
    std::string escape_json_string(const std::string& str);
    
    // XML generation helpers
    std::string generate_xml_header();
    std::string generate_xml_element(const std::string& tag,
                                    const std::string& content,
                                    const std::map<std::string, std::string>& attributes = {});
    std::string escape_xml_string(const std::string& str);
    
    // Text generation helpers
    std::string generate_text_header(const std::string& title);
    std::string generate_text_table(const std::vector<std::string>& headers,
                                   const std::vector<std::vector<std::string>>& rows);
    std::string generate_text_separator(char separator = '-', size_t length = 80);
    
    // Utility methods
    std::string format_threat_level(ThreatLevel level);
    std::string format_anomaly_type(AnomalyType type);
    std::string format_timestamp(const std::chrono::system_clock::time_point& time);
    std::string format_bytes(uint64_t bytes);
    std::string format_percentage(double value, double total);
    
    // Template management
    void load_templates();
    std::string apply_template(const std::string& template_str,
                              const std::map<std::string, std::string>& variables);
    
    // File operations
    bool write_file(const std::string& filename, const std::string& content);
    std::string read_template_file(const std::string& template_path);
};

} // namespace nsa

#endif // REPORT_GENERATOR_H

