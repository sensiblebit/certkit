package certkit

import (
	"bufio"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSSHPort          = "22"
	maxSSHVersionLines      = 50
	maxSSHPacketLength      = 256 * 1024
	sshMsgKexInit      byte = 20
)

var (
	errSSHProbeHostRequired  = errors.New("probing SSH server: host is required")
	errSSHVersionLineMissing = errors.New("SSH server did not send a version banner")
	errSSHVersionLineInvalid = errors.New("invalid SSH version banner")
	errSSHPacketTooLarge     = errors.New("SSH packet exceeds size limit")
	errSSHPacketMalformed    = errors.New("malformed SSH packet")
	errSSHUnexpectedPacket   = errors.New("unexpected SSH packet type")
	errSSHKexInitMalformed   = errors.New("malformed SSH KEXINIT packet")
)

// SSHProbeInput configures ProbeSSH.
type SSHProbeInput struct {
	// Host is the SSH server hostname or IP address to probe.
	Host string
	// Port is the optional TCP port to probe. When empty, ProbeSSH uses 22.
	Port string
	// Policy enables optional heuristic transport-policy diagnostics.
	Policy SecurityPolicy
}

// SSHProbeResult contains the server banner and advertised SSH transport algorithms.
type SSHProbeResult struct {
	Host                      string            `json:"host"`
	Port                      string            `json:"port"`
	Policy                    SecurityPolicy    `json:"policy,omitempty"`
	Protocol                  string            `json:"protocol"`
	Banner                    string            `json:"banner"`
	SoftwareVersion           string            `json:"software_version,omitempty"`
	KeyExchangeAlgorithms     []string          `json:"key_exchange_algorithms"`
	KeyExchangeExtensions     []string          `json:"key_exchange_extensions,omitempty"`
	HostKeyAlgorithms         []string          `json:"host_key_algorithms"`
	CiphersClientToServer     []string          `json:"ciphers_client_to_server"`
	CiphersServerToClient     []string          `json:"ciphers_server_to_client"`
	MACsClientToServer        []string          `json:"macs_client_to_server"`
	MACsServerToClient        []string          `json:"macs_server_to_client"`
	CompressionClientToServer []string          `json:"compression_client_to_server"`
	CompressionServerToClient []string          `json:"compression_server_to_client"`
	Diagnostics               []ChainDiagnostic `json:"diagnostics,omitempty"`
	OverallRating             CipherRating      `json:"overall_rating,omitempty"`
}

// ProbeSSH connects to an SSH server, captures its banner, and parses the
// advertised transport algorithms from the initial KEXINIT packet.
func ProbeSSH(ctx context.Context, input SSHProbeInput) (*SSHProbeResult, error) {
	if input.Host == "" {
		return nil, errSSHProbeHostRequired
	}
	port := input.Port
	if port == "" {
		port = defaultSSHPort
	}
	addr := net.JoinHostPort(input.Host, port)

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSH server %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()
	stopOnCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopOnCancel()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("setting SSH probe deadline: %w", err)
		}
	} else if err := conn.SetDeadline(time.Now().Add(defaultConnectTimeout)); err != nil {
		return nil, fmt.Errorf("setting SSH probe deadline: %w", err)
	}

	reader := bufio.NewReader(conn)
	banner, err := readSSHBanner(reader)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(conn, "SSH-2.0-certkit\r\n"); err != nil {
		return nil, fmt.Errorf("writing SSH client banner: %w", err)
	}

	payload, err := readSSHPacket(reader)
	if err != nil {
		return nil, err
	}

	result, err := parseSSHKexInit(payload)
	if err != nil {
		return nil, err
	}

	protocol, software := parseSSHBanner(banner)
	result.Host = input.Host
	result.Port = port
	result.Policy = input.Policy
	result.Protocol = protocol
	result.Banner = banner
	result.SoftwareVersion = software
	result.Diagnostics = DiagnoseSSHProbe(result)
	SortDiagnostics(result.Diagnostics)
	result.OverallRating = RateSSHAlgorithms(result)
	return result, nil
}

func readSSHBanner(reader *bufio.Reader) (string, error) {
	for range maxSSHVersionLines {
		line, err := readTextLine(reader)
		if err != nil {
			return "", fmt.Errorf("reading SSH version banner: %w", err)
		}
		if strings.HasPrefix(line, "SSH-") {
			if protocol, _ := parseSSHBanner(line); protocol == "" {
				return "", errSSHVersionLineInvalid
			}
			return line, nil
		}
	}
	return "", errSSHVersionLineMissing
}

func readSSHPacket(reader *bufio.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, fmt.Errorf("reading SSH packet header: %w", err)
	}
	packetLen := binary.BigEndian.Uint32(header[:4])
	if packetLen > maxSSHPacketLength {
		return nil, fmt.Errorf("%w: %d bytes", errSSHPacketTooLarge, packetLen)
	}
	paddingLen := int(header[4])
	if packetLen < 1 || paddingLen < 4 {
		return nil, errSSHPacketMalformed
	}
	body := make([]byte, packetLen-1)
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, fmt.Errorf("reading SSH packet body: %w", err)
	}
	if paddingLen > len(body) {
		return nil, errSSHPacketMalformed
	}
	payload := body[:len(body)-paddingLen]
	if len(payload) == 0 {
		return nil, errSSHPacketMalformed
	}
	return payload, nil
}

func parseSSHKexInit(payload []byte) (*SSHProbeResult, error) {
	if len(payload) < 17 {
		return nil, errSSHKexInitMalformed
	}
	if payload[0] != sshMsgKexInit {
		return nil, fmt.Errorf("%w: %d", errSSHUnexpectedPacket, payload[0])
	}

	pos := 1 + 16 // msg code + cookie
	readNameLists := func() ([]string, error) {
		if pos+4 > len(payload) {
			return nil, errSSHKexInitMalformed
		}
		n := binary.BigEndian.Uint32(payload[pos : pos+4])
		pos += 4
		if strconv.IntSize == 32 && n > 1<<31-1 {
			return nil, errSSHKexInitMalformed
		}
		nameListLen := int(n)
		if nameListLen > len(payload)-pos {
			return nil, errSSHKexInitMalformed
		}
		raw := string(payload[pos : pos+nameListLen])
		pos += nameListLen
		if raw == "" {
			return []string{}, nil
		}
		return strings.Split(raw, ","), nil
	}

	result := &SSHProbeResult{}
	var err error
	if result.KeyExchangeAlgorithms, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.HostKeyAlgorithms, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.CiphersClientToServer, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.CiphersServerToClient, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.MACsClientToServer, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.MACsServerToClient, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.CompressionClientToServer, err = readNameLists(); err != nil {
		return nil, err
	}
	if result.CompressionServerToClient, err = readNameLists(); err != nil {
		return nil, err
	}
	if _, err = readNameLists(); err != nil { // languages c->s
		return nil, err
	}
	if _, err = readNameLists(); err != nil { // languages s->c
		return nil, err
	}
	if pos+5 > len(payload) {
		return nil, errSSHKexInitMalformed
	}
	result.normalize()
	return result, nil
}

func (r *SSHProbeResult) normalize() {
	if r == nil {
		return
	}
	var algorithms []string
	var extensions []string
	for _, value := range r.KeyExchangeAlgorithms {
		if isSSHKexExtension(value) {
			extensions = append(extensions, value)
			continue
		}
		algorithms = append(algorithms, value)
	}
	r.KeyExchangeAlgorithms = algorithms
	r.KeyExchangeExtensions = extensions
}

func parseSSHBanner(banner string) (string, string) {
	trimmed := strings.TrimSpace(banner)
	if !strings.HasPrefix(trimmed, "SSH-") {
		return "", ""
	}
	rest := strings.TrimPrefix(trimmed, "SSH-")
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) != 2 || parts[0] == "" {
		return "", ""
	}
	protocol := "SSH " + parts[0]
	software := parts[1]
	if idx := strings.IndexByte(software, ' '); idx != -1 {
		software = software[:idx]
	}
	return protocol, software
}

// FormatSSHProbeResult formats an SSHProbeResult as human-readable text.
func FormatSSHProbeResult(r *SSHProbeResult) string {
	var out strings.Builder
	fmt.Fprintf(&out, "Host:         %s:%s\n", r.Host, r.Port)
	if r.Policy.Enabled() {
		fmt.Fprintf(&out, "Policy:       %s heuristic\n", r.Policy.DisplayName())
	}
	fmt.Fprintf(&out, "Protocol:     %s\n", r.Protocol)
	fmt.Fprintf(&out, "Banner:       %s\n", r.Banner)
	if r.SoftwareVersion != "" {
		fmt.Fprintf(&out, "Software:     %s\n", r.SoftwareVersion)
	}
	if line := FormatSSHRatingLine(r); line != "" {
		out.WriteString(line)
	}
	if len(r.Diagnostics) > 0 {
		out.WriteString("\nDiagnostics:\n")
		for _, d := range r.Diagnostics {
			tag := "WARN"
			if d.Status == "error" {
				tag = "ERR"
			}
			fmt.Fprintf(&out, "  [%s] %s: %s\n", tag, d.Check, d.Detail)
		}
	}
	writeSSHKexSection(&out, r)
	if len(r.KeyExchangeExtensions) > 0 {
		writeSSHListSection(&out, sshListSectionInput{
			title:  "KEX Extensions",
			values: r.KeyExchangeExtensions,
		})
	}
	writeSSHHostKeySection(&out, r)
	writeSSHCipherSection(&out, r)
	writeSSHMACSection(&out, r)
	writeSSHDirectionalSection(&out, sshDirectionalSectionInput{
		title: "Compression",
		c2s:   r.CompressionClientToServer,
		s2c:   r.CompressionServerToClient,
	})
	return out.String()
}

// RateSSHAlgorithms reports an overall SSH transport rating based on the
// advertised algorithm sets. Any weak algorithm offering makes the result weak.
func RateSSHAlgorithms(r *SSHProbeResult) CipherRating {
	if r == nil {
		return ""
	}
	if sshWeakAlgorithmCount(r) > 0 || sshPolicyViolationCount(r) > 0 {
		return CipherRatingWeak
	}
	return CipherRatingGood
}

// DiagnoseSSHProbe summarizes weak or deprecated SSH transport algorithms.
func DiagnoseSSHProbe(r *SSHProbeResult) []ChainDiagnostic {
	if r == nil {
		return nil
	}
	var diags []ChainDiagnostic

	if weak := weakSSHValues(r.KeyExchangeAlgorithms, isWeakSSHKex); len(weak) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "weak-kex",
			Status: "warn",
			Detail: "server advertises weak or deprecated key exchange algorithms: " + strings.Join(weak, ", "),
		})
	}
	if weak := weakSSHValues(r.HostKeyAlgorithms, isWeakSSHHostKey); len(weak) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "weak-hostkey",
			Status: "warn",
			Detail: "server advertises weak or deprecated host key algorithms: " + strings.Join(weak, ", "),
		})
	}
	if weak := weakSSHValues(slices.Concat(r.CiphersClientToServer, r.CiphersServerToClient), isWeakSSHCipher); len(weak) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "weak-cipher",
			Status: "warn",
			Detail: "server advertises weak or deprecated ciphers: " + strings.Join(weak, ", "),
		})
	}
	if weak := weakSSHValues(slices.Concat(r.MACsClientToServer, r.MACsServerToClient), isWeakSSHMAC); len(weak) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "weak-mac",
			Status: "warn",
			Detail: "server advertises weak or deprecated MACs: " + strings.Join(weak, ", "),
		})
	}

	diags = append(diags, diagnoseSSHPolicy(r)...)

	return diags
}

// FormatSSHRatingLine formats a one-line summary of the SSH transport rating.
func FormatSSHRatingLine(r *SSHProbeResult) string {
	if r == nil {
		return ""
	}
	weak := sshWeakAlgorithmCount(r)
	policyViolations := sshPolicyViolationCount(r)
	rating := r.OverallRating
	if rating == "" {
		rating = RateSSHAlgorithms(r)
	}
	switch {
	case weak == 0 && policyViolations == 0:
		if r.Policy.Enabled() {
			return fmt.Sprintf("Algorithms:   %s (%d weak, %d likely not authorized by %s)\n", rating, weak, policyViolations, r.Policy.DisplayName())
		}
		return fmt.Sprintf("Algorithms:   %s (%d weak)\n", rating, weak)
	case !r.Policy.Enabled():
		return fmt.Sprintf("Algorithms:   %s (%d weak)\n", rating, weak)
	case weak == 0:
		return fmt.Sprintf("Algorithms:   %s (%d likely not authorized by %s)\n", rating, policyViolations, r.Policy.DisplayName())
	default:
		return fmt.Sprintf("Algorithms:   %s (%d weak/deprecated, %d likely not authorized by %s)\n", rating, weak, policyViolations, r.Policy.DisplayName())
	}
}

func sshWeakAlgorithmCount(r *SSHProbeResult) int {
	if r == nil {
		return 0
	}
	return len(weakSSHValues(r.KeyExchangeAlgorithms, isWeakSSHKex)) +
		len(weakSSHValues(r.HostKeyAlgorithms, isWeakSSHHostKey)) +
		len(weakSSHValues(slices.Concat(r.CiphersClientToServer, r.CiphersServerToClient), isWeakSSHCipher)) +
		len(weakSSHValues(slices.Concat(r.MACsClientToServer, r.MACsServerToClient), isWeakSSHMAC))
}

func sshPolicyViolationCount(r *SSHProbeResult) int {
	if r == nil || !r.Policy.Enabled() {
		return 0
	}
	return len(weakSSHValues(r.KeyExchangeAlgorithms, sshPolicyDisallowsKex(r.Policy))) +
		len(weakSSHValues(r.HostKeyAlgorithms, sshPolicyDisallowsHostKey(r.Policy))) +
		len(weakSSHValues(slices.Concat(r.CiphersClientToServer, r.CiphersServerToClient), sshPolicyDisallowsCipher(r.Policy))) +
		len(weakSSHValues(slices.Concat(r.MACsClientToServer, r.MACsServerToClient), sshPolicyDisallowsMAC(r.Policy)))
}

func weakSSHValues(values []string, fn func(string) bool) []string {
	seen := make(map[string]bool)
	weak := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		if fn(value) {
			weak = append(weak, value)
		}
	}
	return weak
}

func isWeakSSHKex(value string) bool {
	// This intentionally sticks to obvious legacy SSH KEX issues: SHA-1 and
	// the small group1 DH family. group14-sha256 is left out on purpose for
	// compatibility; stricter environments should use Policy-based filtering.
	return strings.Contains(value, "group1-sha1") ||
		strings.HasSuffix(value, "-sha1") ||
		strings.Contains(value, "group-exchange-sha1")
}

func isSSHKexExtension(value string) bool {
	return value == "ext-info-s" || value == "kex-strict-s-v00@openssh.com"
}

func isWeakSSHHostKey(value string) bool {
	return value == "ssh-rsa" || value == "ssh-dss"
}

func isWeakSSHCipher(value string) bool {
	return strings.Contains(value, "cbc") ||
		strings.Contains(value, "3des") ||
		strings.Contains(value, "arcfour") ||
		strings.Contains(value, "blowfish") ||
		value == "none"
}

func isWeakSSHMAC(value string) bool {
	return strings.Contains(value, "md5") ||
		strings.Contains(value, "sha1") ||
		strings.Contains(value, "umac-64") ||
		value == "none"
}

func diagnoseSSHPolicy(r *SSHProbeResult) []ChainDiagnostic {
	if r == nil || !r.Policy.Enabled() {
		return nil
	}

	// FIPS 140-2 and FIPS 140-3 share the same conservative SSH allowlist here.
	// The wire protocol exposes advertised algorithms, not whether the remote
	// implementation is running a validated module in an approved mode.
	var diags []ChainDiagnostic
	if disallowed := weakSSHValues(r.KeyExchangeAlgorithms, sshPolicyDisallowsKex(r.Policy)); len(disallowed) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "profile-kex",
			Status: "warn",
			Detail: formatLikelyNotAuthorizedDetail(likelyNotAuthorizedDetailInput{
				policy:   r.Policy,
				singular: "key exchange algorithm",
				plural:   "key exchange algorithms",
				items:    disallowed,
			}),
		})
	}
	if disallowed := weakSSHValues(r.HostKeyAlgorithms, sshPolicyDisallowsHostKey(r.Policy)); len(disallowed) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "profile-hostkey",
			Status: "warn",
			Detail: formatLikelyNotAuthorizedDetail(likelyNotAuthorizedDetailInput{
				policy:   r.Policy,
				singular: "host key algorithm",
				plural:   "host key algorithms",
				items:    disallowed,
			}),
		})
	}
	if disallowed := weakSSHValues(slices.Concat(r.CiphersClientToServer, r.CiphersServerToClient), sshPolicyDisallowsCipher(r.Policy)); len(disallowed) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "profile-cipher",
			Status: "warn",
			Detail: formatLikelyNotAuthorizedDetail(likelyNotAuthorizedDetailInput{
				policy:   r.Policy,
				singular: "cipher",
				plural:   "ciphers",
				items:    disallowed,
			}),
		})
	}
	if disallowed := weakSSHValues(slices.Concat(r.MACsClientToServer, r.MACsServerToClient), sshPolicyDisallowsMAC(r.Policy)); len(disallowed) > 0 {
		diags = append(diags, ChainDiagnostic{
			Check:  "profile-mac",
			Status: "warn",
			Detail: formatLikelyNotAuthorizedDetail(likelyNotAuthorizedDetailInput{
				policy:   r.Policy,
				singular: "MAC",
				plural:   "MACs",
				items:    disallowed,
			}),
		})
	}

	return diags
}

func sshPolicyDisallowsKex(policy SecurityPolicy) func(string) bool {
	return func(value string) bool {
		if !policy.Enabled() {
			return false
		}
		// FIPS 140-2 and FIPS 140-3 intentionally share the same conservative
		// SSH transport allowlist here. Wire-level probing cannot determine
		// validated module state or approved-mode configuration.
		switch value {
		case "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
			"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha256":
			return false
		default:
			return true
		}
	}
}

func sshPolicyDisallowsHostKey(policy SecurityPolicy) func(string) bool {
	return func(value string) bool {
		if !policy.Enabled() {
			return false
		}
		// FIPS 140-2 and FIPS 140-3 intentionally share the same conservative
		// SSH transport allowlist here. Wire-level probing cannot determine
		// validated module state or approved-mode configuration.
		switch value {
		case "rsa-sha2-256", "rsa-sha2-512", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
			return false
		default:
			return true
		}
	}
}

func sshPolicyDisallowsCipher(policy SecurityPolicy) func(string) bool {
	return func(value string) bool {
		if !policy.Enabled() {
			return false
		}
		// FIPS 140-2 and FIPS 140-3 intentionally share the same conservative
		// SSH transport allowlist here. Wire-level probing cannot determine
		// validated module state or approved-mode configuration.
		switch value {
		case "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr":
			return false
		default:
			return true
		}
	}
}

func sshPolicyDisallowsMAC(policy SecurityPolicy) func(string) bool {
	return func(value string) bool {
		if !policy.Enabled() {
			return false
		}
		// FIPS 140-2 and FIPS 140-3 intentionally share the same conservative
		// SSH transport allowlist here. Wire-level probing cannot determine
		// validated module state or approved-mode configuration.
		switch value {
		case "hmac-sha2-256", "hmac-sha2-512", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com":
			return false
		default:
			return true
		}
	}
}

type sshListSectionInput struct {
	title  string
	values []string
}

func writeSSHListSection(out *strings.Builder, input sshListSectionInput) {
	fmt.Fprintf(out, "\n%s (%d):\n", input.title, len(input.values))
	for _, value := range input.values {
		fmt.Fprintf(out, "  %s\n", value)
	}
}

type sshDirectionalSectionInput struct {
	title string
	c2s   []string
	s2c   []string
}

func writeSSHDirectionalSection(out *strings.Builder, input sshDirectionalSectionInput) {
	if slices.Equal(input.c2s, input.s2c) {
		writeSSHListSection(out, sshListSectionInput{title: input.title, values: input.c2s})
		return
	}
	fmt.Fprintf(out, "\n%s:\n", input.title)
	fmt.Fprintf(out, "  client->server (%d):\n", len(input.c2s))
	for _, value := range input.c2s {
		fmt.Fprintf(out, "    %s\n", value)
	}
	fmt.Fprintf(out, "  server->client (%d):\n", len(input.s2c))
	for _, value := range input.s2c {
		fmt.Fprintf(out, "    %s\n", value)
	}
}

func writeSSHKexSection(out *strings.Builder, r *SSHProbeResult) {
	writeSSHRatedListSection(sshRatedListSectionInput{
		out:    out,
		title:  "Key Exchange",
		values: r.KeyExchangeAlgorithms,
		config: sshRatingConfig{
			policy:   r.Policy,
			weakFn:   isWeakSSHKex,
			policyFn: sshPolicyDisallowsKex,
		},
	})
}

func writeSSHHostKeySection(out *strings.Builder, r *SSHProbeResult) {
	writeSSHRatedListSection(sshRatedListSectionInput{
		out:    out,
		title:  "Host Keys",
		values: r.HostKeyAlgorithms,
		config: sshRatingConfig{
			policy:   r.Policy,
			weakFn:   isWeakSSHHostKey,
			policyFn: sshPolicyDisallowsHostKey,
		},
	})
}

func writeSSHCipherSection(out *strings.Builder, r *SSHProbeResult) {
	writeSSHRatedDirectionalSection(sshRatedDirectionalSectionInput{
		out:   out,
		title: "Ciphers",
		c2s:   r.CiphersClientToServer,
		s2c:   r.CiphersServerToClient,
		config: sshRatingConfig{
			policy:   r.Policy,
			weakFn:   isWeakSSHCipher,
			policyFn: sshPolicyDisallowsCipher,
		},
	})
}

func writeSSHMACSection(out *strings.Builder, r *SSHProbeResult) {
	writeSSHRatedDirectionalSection(sshRatedDirectionalSectionInput{
		out:   out,
		title: "MACs",
		c2s:   r.MACsClientToServer,
		s2c:   r.MACsServerToClient,
		config: sshRatingConfig{
			policy:   r.Policy,
			weakFn:   isWeakSSHMAC,
			policyFn: sshPolicyDisallowsMAC,
		},
	})
}

type sshRatingConfig struct {
	policy   SecurityPolicy
	weakFn   func(string) bool
	policyFn func(SecurityPolicy) func(string) bool
}

type sshRatedListSectionInput struct {
	out       *strings.Builder
	title     string
	values    []string
	preferred string
	config    sshRatingConfig
}

func writeSSHRatedListSection(input sshRatedListSectionInput) {
	preferred := ""
	if len(input.values) > 0 {
		preferred = input.values[0]
	}
	input.preferred = preferred
	writeSSHRatedListSectionWithPreferred(input)
}

func writeSSHRatedListSectionWithPreferred(input sshRatedListSectionInput) {
	values := sortSSHDisplayValues(sshDisplayValuesInput{
		values: input.values,
		config: input.config,
	})
	fmt.Fprintf(input.out, "\n%s (%d):\n", input.title, len(values))
	for _, value := range values {
		fmt.Fprintf(
			input.out,
			"  %s %-16s %s\n",
			sshPreferenceMarker(value, input.preferred),
			sshAlgorithmTag(sshAlgorithmStatusInput{value: value, config: input.config}),
			value,
		)
	}
}

type sshRatedDirectionalSectionInput struct {
	out    *strings.Builder
	title  string
	c2s    []string
	s2c    []string
	config sshRatingConfig
}

func writeSSHRatedDirectionalSection(input sshRatedDirectionalSectionInput) {
	origC2S := slices.Clone(input.c2s)
	origS2C := slices.Clone(input.s2c)
	preferredC2S := ""
	if len(input.c2s) > 0 {
		preferredC2S = input.c2s[0]
	}
	preferredS2C := ""
	if len(input.s2c) > 0 {
		preferredS2C = input.s2c[0]
	}
	c2s := sortSSHDisplayValues(sshDisplayValuesInput{
		values: input.c2s,
		config: input.config,
	})
	s2c := sortSSHDisplayValues(sshDisplayValuesInput{
		values: input.s2c,
		config: input.config,
	})
	if slices.Equal(origC2S, origS2C) {
		writeSSHRatedListSectionWithPreferred(sshRatedListSectionInput{
			out:       input.out,
			title:     input.title,
			values:    c2s,
			preferred: preferredC2S,
			config:    input.config,
		})
		return
	}
	fmt.Fprintf(input.out, "\n%s:\n", input.title)
	fmt.Fprintf(input.out, "  client->server (%d):\n", len(c2s))
	for _, value := range c2s {
		fmt.Fprintf(
			input.out,
			"    %s %-16s %s\n",
			sshPreferenceMarker(value, preferredC2S),
			sshAlgorithmTag(sshAlgorithmStatusInput{value: value, config: input.config}),
			value,
		)
	}
	fmt.Fprintf(input.out, "  server->client (%d):\n", len(s2c))
	for _, value := range s2c {
		fmt.Fprintf(
			input.out,
			"    %s %-16s %s\n",
			sshPreferenceMarker(value, preferredS2C),
			sshAlgorithmTag(sshAlgorithmStatusInput{value: value, config: input.config}),
			value,
		)
	}
}

type sshAlgorithmStatusInput struct {
	value  string
	config sshRatingConfig
}

func sshAlgorithmTag(input sshAlgorithmStatusInput) string {
	isWeak := input.config.weakFn(input.value)
	isPolicy := input.config.policy.Enabled() && input.config.policyFn(input.config.policy)(input.value)
	switch {
	case isWeak && isPolicy:
		return "[weak, profile]"
	case isWeak:
		return "[weak]"
	case isPolicy:
		return "[profile]"
	default:
		return "[good]"
	}
}

type sshDisplayValuesInput struct {
	values []string
	config sshRatingConfig
}

func sortSSHDisplayValues(input sshDisplayValuesInput) []string {
	sorted := slices.Clone(input.values)
	slices.SortStableFunc(sorted, func(a, b string) int {
		return cmp.Compare(
			sshAlgorithmStatusRank(sshAlgorithmStatusInput{value: a, config: input.config}),
			sshAlgorithmStatusRank(sshAlgorithmStatusInput{value: b, config: input.config}),
		)
	})
	return sorted
}

func sshAlgorithmStatusRank(input sshAlgorithmStatusInput) int {
	isWeak := input.config.weakFn(input.value)
	isPolicy := input.config.policy.Enabled() && input.config.policyFn(input.config.policy)(input.value)
	switch {
	case !isWeak && !isPolicy:
		return 0
	case isWeak && !isPolicy:
		return 1
	case !isWeak && isPolicy:
		return 2
	default:
		return 3
	}
}

func sshPreferenceMarker(value, preferred string) string {
	if preferred != "" && value == preferred {
		return ">"
	}
	return " "
}
