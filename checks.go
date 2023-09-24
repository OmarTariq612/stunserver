package stunserver

// CheckOverflow returns ErrAttributeSizeOverflow if got is bigger that max.
func CheckOverflow(_ AttrType, got, max int) error {
	if got <= max {
		return nil
	}
	return ErrAttributeSizeOverflow
}
