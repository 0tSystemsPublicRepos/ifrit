package payload

import (
	"log"
)

// AddCondition adds a condition to a payload template
func (pm *PayloadManager) AddCondition(payloadID int, conditionType, conditionValue, operator string) error {
	err := pm.db.AddPayloadCondition(int64(payloadID), conditionType, conditionValue, operator)
	if err != nil {
		log.Printf("Error adding condition: %v", err)
		return err
	}
	return nil
}



// RemoveCondition removes a condition from a payload template
func (pm *PayloadManager) RemoveCondition(conditionID int) error {
	return pm.db.RemovePayloadCondition(int64(conditionID))
}


// GetConditionsForPayload retrieves all conditions for a payload
func (pm *PayloadManager) GetConditionsForPayload(payloadID int) ([]PayloadCondition, error) {
	results, err := pm.db.GetPayloadConditions(int64(payloadID))
	if err != nil {
		return nil, err
	}

	var conditions []PayloadCondition
	for _, result := range results {
		conditions = append(conditions, PayloadCondition{
			ID:             result["id"].(int64),
			ConditionType:  result["condition_type"].(string),
			ConditionValue: result["condition_value"].(string),
			Operator:       result["operator"].(string),
		})
	}

	return conditions, nil
}


// UpdateCondition updates an existing condition
func (pm *PayloadManager) UpdateCondition(conditionID int, conditionType, conditionValue, operator string) error {
	return pm.db.UpdatePayloadCondition(int64(conditionID), conditionType, conditionValue, operator)
}
