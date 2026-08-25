package model

// ADInventory is the directory snapshot obtained from an LDAP/Active
// Directory server during one scan. It deliberately models directory objects
// separately from machines: a user, group, OU or GPO must never be faked as
// an endpoint asset.
type ADInventory struct {
	DomainDNSName string
	Users         []ADUser
	Groups        []ADGroup
	OUs           []ADOrganizationalUnit
	GPOs          []ADGroupPolicyObject
	Computers     []ADComputer
	Domains       []ADDomain
}

type ADDomain struct {
	DistinguishedName string
	DNSRoot           string
	NetBIOSName       string
	ObjectSID         string
	WhenCreated       string
}

type ADComputer struct {
	DistinguishedName      string
	Name                   string
	DNSHostName            string
	OperatingSystem        string
	OperatingSystemVersion string
	ObjectSID              string
	Enabled                bool
	LastLogon              string
	PasswordLastSet        string
	ServicePrincipalNames  []string
}

type ADUser struct {
	DistinguishedName    string
	SAMAccountName       string
	UserPrincipalName    string
	DisplayName          string
	Mail                 string
	ObjectSID            string
	Enabled              bool
	Department           string
	Title                string
	Manager              string
	Telephone            string
	LastLogon            string
	WhenCreated          string
	AccountExpires       string
	PasswordNeverExpires bool
	PasswordNotRequired  bool
	MemberOf             []string
}

type ADGroup struct {
	DistinguishedName string
	SAMAccountName    string
	ObjectSID         string
	Description       string
	GroupType         string
	Members           []string
}

type ADOrganizationalUnit struct {
	DistinguishedName string
	Name              string
	GPOLinks          []string
	Description       string
}

type ADGroupPolicyObject struct {
	DistinguishedName string
	DisplayName       string
	GUID              string
	Version           string
	Flags             string
}
