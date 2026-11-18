package migration

import (
	"reflect"
	"testing"
)

func TestPlanSFTPGoCalendarExpandsFiniteCronFields(t *testing.T) {
	for _, tc := range []struct {
		hour, weekday string
		times         []string
		days          []int
	}{
		{"4-8", "*", []string{"04:00:00", "05:00:00", "06:00:00", "07:00:00", "08:00:00"}, []int{0, 1, 2, 3, 4, 5, 6}},
		{"2,04-08/2,23,8", "Mon-Wed,Sat", []string{"02:00:00", "04:00:00", "06:00:00", "08:00:00", "23:00:00"}, []int{1, 2, 3, 6}},
		{"*/6", "1/2", []string{"00:00:00", "06:00:00", "12:00:00", "18:00:00"}, []int{1, 3, 5}},
		{"19/3", "?", []string{"19:00:00", "22:00:00"}, []int{0, 1, 2, 3, 4, 5, 6}},
	} {
		got := sftpgoCalendar(&sftpgoSchedule{Hour: tc.hour, DayOfWeek: tc.weekday, DayOfMonth: "*", Month: "*"})
		want := &CalendarFragment{"UTC", tc.times, tc.days}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s %s: got %#v, want %#v", tc.hour, tc.weekday, got, want)
		}
	}
}

func TestPlanSFTPGoCalendarRefusesOutOfProfileExpressions(t *testing.T) {
	for _, tc := range []sftpgoSchedule{
		{Hour: "3,4,", DayOfWeek: "*", DayOfMonth: "*", Month: "*"},
		{Hour: "23-25", DayOfWeek: "*", DayOfMonth: "*", Month: "*"},
		{Hour: "*/0", DayOfWeek: "*", DayOfMonth: "*", Month: "*"},
		{Hour: "*/4/2", DayOfWeek: "*", DayOfMonth: "*", Month: "*"},
		{Hour: "Fri", DayOfWeek: "*", DayOfMonth: "*", Month: "*"},
		{Hour: "07", DayOfWeek: "Sat-Sun", DayOfMonth: "*", Month: "*"},
		{Hour: "07", DayOfWeek: "7", DayOfMonth: "*", Month: "*"},
		{Hour: "07", DayOfWeek: "2", DayOfMonth: "1", Month: "*"},
		{Hour: "07", DayOfWeek: "2", DayOfMonth: "*", Month: "Jan"},
	} {
		if fragment := sftpgoCalendar(&tc); fragment != nil {
			t.Errorf("out-of-profile fields %#v acquired calendar %#v", tc, fragment)
		}
	}
}
