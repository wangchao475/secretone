package api

import "strings"

// Error
var (
	ErrAccessLevelUnknown = errAPI.Code("access_level_unknown").Error("The access level is not known")
)

// Permission defines what kind of access an access rule grants or a access level has.
type Permission []string

// The different Permission options.
const (
	PermissionNone   = "none"
	PermissionRead   = "read"
	PermissionWrite  = "write"
	PermissionDelete = "delete" //tina add
	//PermissionAdmin  //不需要admin角色，每个权限只对应单一功能
)

func (s *Permission) Set(value string) error {
	//兼容方法
	if strings.Contains(value, ",") {
		valueArr := strings.Split(value, ",")
		for _, perValue := range valueArr {
			switch perValue {
			case "r", "read":
				*s = append(*s, PermissionRead)
			case "w", "write":
				*s = append(*s, PermissionWrite)
			case "d", "delete":
				*s = append(*s, PermissionDelete)
			//case "a", "admin":
			//	*al = PermissionAdmin
			case "n", "none":
				*s = append(*s, PermissionNone)
			default:
				return ErrAccessLevelUnknown
			}
		}
	} else {
		switch value {
		case "r", "read":
			*s = append(*s, PermissionRead)
		case "w", "write":
			*s = append(*s, PermissionWrite)
		case "d", "delete":
			*s = append(*s, PermissionDelete)
		//case "a", "admin":
		//	*al = PermissionAdmin
		case "n", "none":
			*s = append(*s, PermissionNone)
		default:
			return ErrAccessLevelUnknown
		}
	}
	return nil
}

// Set sets the Permission to the value.
//func (al *Permission) Set(value string) error {
//	switch value {
//	case "r", "read":
//		*al = PermissionRead
//	case "w", "write":
//		*al = PermissionWrite
//	case "d", "delete":
//		*al = PermissionDelete
//	//case "a", "admin":
//	//	*al = PermissionAdmin
//	case "n", "none":
//		*al = PermissionNone
//	default:
//		return ErrAccessLevelUnknown
//	}
//	return nil
//}
//func (al *Permission) Set(value string) error {
//	valueArr := strings.Split(value,",")
//	var finalPermission []string
//	for _,perValue := range valueArr{
//		switch perValue {
//		case "r", "read":
//			finalPermission = append(finalPermission,PermissionRead)
//		case "w", "write":
//			finalPermission = append(finalPermission,PermissionWrite)
//		case "d", "delete":
//			finalPermission = append(finalPermission,PermissionDelete)
//		case "n", "none":
//			finalPermission = append(finalPermission,PermissionNone)
//		default:
//			return ErrAccessLevelUnknown
//		}
//	}
//	finalString := strings.Join(finalPermission,",")
//	var tmp string
//	tmp = "aaa"
//	al = tmp
//	return nil
//}
//func (al Permission) String() string {
//	switch al {
//	case PermissionRead:
//		return "1"
//	case PermissionWrite:
//		return "2"
//	case PermissionDelete:
//		return "3"
//	//case PermissionAdmin:
//	//	return "admin"
//	default:
//		return "0"
//	}
//}
//func (al Permission) Int() int {
//	switch al {
//	case PermissionRead:
//		return 1
//	case PermissionWrite:
//		return 2
//	case PermissionDelete:
//		return 3
//	//case PermissionAdmin:
//	//	return "admin"
//	default:
//		return 0
//	}
//}
//func (al Permission) String() string {
//	switch al {
//	case PermissionRead:
//		return "read"
//	case PermissionWrite:
//		return "write"
//	case PermissionDelete:
//		return "delete"
//	default:
//		return "none"
//	}
//}
func (al Permission) String() string {
	if len(al) != 0 {
		return strings.Join(al, ",")
	} else {
		return ""
	}
}
