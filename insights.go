package main

import (
	"fmt"
	"go/version"
	"sort"
	"time"

	"golang.org/x/mod/semver"
)

// AssessCompatibility is a metadata-based estimate, never a test or API guarantee.
func AssessCompatibility(d Dependency, projectGo string) Compatibility {
	c := Compatibility{Risk: "unknown"}
	if d.Replaced {
		c.Reasons = []string{"Replace uygulanmış; hedef bağımlılık ayrıca incelenmeli."}
		return c
	}
	if !semver.IsValid(d.Version) || !semver.IsValid(d.LatestVersion) {
		c.Reasons = []string{"Karşılaştırılabilir sürüm bilgisi alınamadı."}
		return c
	}
	if semver.Compare(d.LatestVersion, d.Version) <= 0 {
		c.Risk = "none"
		c.Reasons = []string{"Daha yeni bir hedef sürüm bildirilmedi."}
		return c
	}
	c.Risk = "low"
	c.Reasons = append(c.Reasons, "Semver uyumluluk tahmini; isteğe bağlı derleme/test sonuçları ayrı değerlendirilir.")
	if semver.Major(d.Version) != semver.Major(d.LatestVersion) {
		c.Risk = "high"
		c.Reasons = append(c.Reasons, "Major sürüm değişiyor; kırıcı API değişiklikleri beklenebilir.")
	}
	if semver.Major(d.Version) == "v0" {
		c.Risk = "high"
		c.Reasons = append(c.Reasons, "v0 sürümlerinde geriye dönük uyumluluk taahhüdü yoktur.")
	}
	if semver.Prerelease(d.Version) != "" || semver.Prerelease(d.LatestVersion) != "" {
		c.Risk = "high"
		c.Reasons = append(c.Reasons, "Ön sürüm veya pseudo-version geçişi; elle inceleme gerekli.")
	}
	if version.IsValid("go"+d.LatestGoVersion) && version.IsValid("go"+projectGo) {
		if version.Compare("go"+d.LatestGoVersion, "go"+projectGo) > 0 {
			c.Risk = "high"
			c.Reasons = append(c.Reasons, fmt.Sprintf("Hedef Go %s istiyor; proje go direktifi %s. Go tabanı yükseltilmeli.", d.LatestGoVersion, projectGo))
		}
	} else {
		if c.Risk == "low" {
			c.Risk = "unknown"
		}
		c.Reasons = append(c.Reasons, "Go sürümü gereksinimi karşılaştırılamadı.")
	}
	if d.MetadataError != "" {
		if c.Risk == "low" {
			c.Risk = "unknown"
		}
		c.Reasons = append(c.Reasons, "Hedef sürüm meta verisi eksik.")
	}
	return c
}

func AssessDependencies(modules []*Module, minimumAge time.Duration, now time.Time) {
	for _, m := range modules {
		for i := range m.Requires {
			d := &m.Requires[i]
			d.Compatibility = AssessCompatibility(*d, m.GoVersion)
			for _, excluded := range m.Excludes {
				if excluded.Path == d.Path && excluded.Version == d.LatestVersion && isUpdate(d.UpdateKind) {
					d.Compatibility.Risk = "high"
					d.Compatibility.Reasons = append(d.Compatibility.Reasons, "Hedef sürüm go.mod exclude direktifiyle yasaklanmış; kural incelenmeli.")
				}
			}
			d.ReleaseStatus = "unknown"
			if isUpdate(d.UpdateKind) && d.LatestTime != nil {
				if now.Sub(*d.LatestTime) < minimumAge {
					d.ReleaseStatus = "young"
				} else {
					d.ReleaseStatus = "mature"
				}
			}
		}
	}
}

func buildInsights(r *Report) {
	vulnerable := map[string]bool{}
	for _, m := range r.Modules {
		for _, d := range m.Requires {
			if d.Security.Status != "" && d.Security.Status != "unchecked" {
				r.CheckedVulnerabilities = true
			}
			if d.Security.Status == "checked" {
				r.SecurityChecked++
			} else if d.Security.Status != "" && d.Security.Status != "unchecked" {
				r.SecurityUnavailable++
			}
			if len(d.Security.Vulnerabilities) > 0 {
				vulnerable[d.Path] = true
			}
			for _, failure := range []string{d.MetadataError, d.Security.Error, d.TargetSecurity.Error} {
				if failure != "" {
					r.Errors = append(r.Errors, ScanError{Path: m.Dir + " → " + d.Path, Error: failure})
				}
			}
			item := ActionItem{Project: m.Path, Dir: m.Dir, Path: d.Path, Current: d.Version, Target: d.LatestVersion}
			switch {
			case len(d.Security.Vulnerabilities) > 0:
				item.Priority = 1
				item.Reason = "Güvenlik bulgusu: yükseltmeyi öncelikli inceleyin."
				if d.TargetSecurity.Status == "checked" && len(d.TargetSecurity.Vulnerabilities) == 0 {
					item.Reason += " Hedef sürümde OSV kaydı bulunmadı; uyumluluk testleri gerekli."
				} else {
					item.Reason += " Hedef sürümün bulguları giderdiği doğrulanmadı."
				}
			case len(d.TargetSecurity.Vulnerabilities) > 0:
				item.Priority = 1
				item.Reason = "Hedef sürümde de güvenlik bulgusu var; bu hedefi güvenli kabul etmeyin."
			case len(d.Retracted) > 0 || d.Deprecated != "":
				item.Priority = 2
				item.Reason = "Geri çekilmiş sürüm veya kullanımdan kaldırılmış modül; alternatif inceleyin."
			case isUpdate(d.UpdateKind) && d.Compatibility.Risk == "high":
				item.Priority = 2
				item.Reason = "Uyumluluk riski yüksek; geçiş planı ve testler gerekli."
			case isUpdate(d.UpdateKind) && d.ReleaseStatus == "young":
				item.Priority = 3
				item.Reason = "Yeni yayımlanmış sürüm; bekleme süresini değerlendirin."
			case isUpdate(d.UpdateKind):
				item.Priority = 4
				item.Reason = "Rutin güncelleme; değişiklik notlarını ve proje testlerini inceleyin."
			default:
				continue
			}
			r.Actions = append(r.Actions, item)
		}
	}
	r.VulnerableDependencies = len(vulnerable)
	sort.SliceStable(r.Actions, func(i, j int) bool {
		a, b := r.Actions[i], r.Actions[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Dir < b.Dir
	})
}

func securityLabel(s string) string {
	switch s {
	case "checked":
		return "Sorgulandı"
	case "private":
		return "Özel modül: sorgulanmadı"
	case "replaced":
		return "Replace: sorgulanmadı"
	case "unavailable":
		return "Bilgi alınamadı"
	default:
		return "Kontrol edilmedi"
	}
}
func riskLabel(s string) string {
	switch s {
	case "high":
		return "Yüksek risk"
	case "low":
		return "Düşük risk (tahmin)"
	case "none":
		return "Sürüm yükseltmesi yok"
	default:
		return "Belirsiz"
	}
}
func releaseLabel(s string) string {
	switch s {
	case "young":
		return "Yeni yayın · bekleme süresi dolmadı"
	case "mature":
		return "Yayın yaşı eşiği aşıldı (güvenlik garantisi değildir)"
	default:
		return "Yayın yaşı bilinmiyor"
	}
}
