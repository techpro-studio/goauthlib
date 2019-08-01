package delivery

type DataDelivery interface {
	Send(destination, message string)error
}
